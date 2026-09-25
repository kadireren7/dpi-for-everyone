#define _GNU_SOURCE
#include "tp_platform.h"
#include "netfingerprint.h"
#include "tp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef IP6T_SO_ORIGINAL_DST
# define IP6T_SO_ORIGINAL_DST 80
#endif
#ifndef SO_MARK
# define SO_MARK 36
#endif

/* ============================================================
 * Linux: nftables REDIRECT (table inet TP_NFT_TABLE, see tp.h for the
 * ruleset), the original destination from conntrack
 * (SO_ORIGINAL_DST), our own sockets excluded by SO_MARK, network
 * changes from rtnetlink.
 * ============================================================ */

/* Feeds `text` to `nft -f -`. Fixed argv, no shell; the text is built
 * only from constants, an int port and inet_ntop() output. stdout/
 * stderr are discarded unless `quiet` is 0. Returns 0 if nft exited 0. */
static int	nft_run(const char *text, size_t len, int quiet)
{
	int		pipefd[2];
	pid_t	pid;
	int		status;
	ssize_t	w;
	size_t	total;
	int		devnull;

	if (pipe2(pipefd, O_CLOEXEC) < 0)
		return (-1);
	pid = fork();
	if (pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		return (-1);
	}
	if (pid == 0)
	{
		dup2(pipefd[0], STDIN_FILENO);
		if (quiet)
		{
			devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0)
			{
				dup2(devnull, STDOUT_FILENO);
				dup2(devnull, STDERR_FILENO);
			}
		}
		execlp("nft", "nft", "-f", "-", (char *)NULL);
		_exit(127);
	}
	close(pipefd[0]);
	total = 0;
	while (total < len)
	{
		w = write(pipefd[1], text + total, len - total);
		if (w < 0 && errno == EINTR)
			continue ;
		if (w <= 0)
			break ;
		total += (size_t)w;
	}
	close(pipefd[1]);
	while (waitpid(pid, &status, 0) < 0)
	{
		if (errno != EINTR)
			return (-1);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);
	return (0);
}

/* What the installed table looks like, for re-arming/reinstalling.
 * Set by the main thread only. */
static int	g_port;
static int	g_ipv6;
static int	g_dns_port;
static int	g_netlink = -1;

int	tpp_init(void)
{
	struct sockaddr_nl	sa;

	g_netlink = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
			NETLINK_ROUTE);
	if (g_netlink < 0)
		return (0);
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
		| RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
	if (bind(g_netlink, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
		close(g_netlink);
		g_netlink = -1;
	}
	return (0);
}

static int	heartbeat(void)
{
	char	buf[512];
	size_t	len;

	len = tp_nft_heartbeat(buf, sizeof(buf), g_dns_port > 0);
	if (len == 0)
		return (-1);
	return (nft_run(buf, len, 1));
}

int	tpp_install(int port, int ipv6, int dns_port)
{
	char	buf[3072];
	size_t	len;

	len = tp_nft_ruleset(buf, sizeof(buf), port, ipv6, dns_port);
	if (len == 0 || nft_run(buf, len, 0) != 0)
		return (-1);
	g_port = port;
	g_ipv6 = ipv6;
	g_dns_port = dns_port;
	return (heartbeat());
}

int	tpp_refresh(void)
{
	/* the refresh fails if our table vanished (e.g. someone ran
	 * `nft flush ruleset`): put it back */
	if (heartbeat() == 0)
		return (0);
	if (tpp_install(g_port, g_ipv6, g_dns_port) == 0)
		return (1);
	return (-1);
}

void	tpp_remove(void)
{
	char	buf[128];
	int		len;

	len = snprintf(buf, sizeof(buf), "table inet %s {}\ndelete table inet %s\n",
			TP_NFT_TABLE, TP_NFT_TABLE);
	if (len > 0)
		nft_run(buf, (size_t)len, 1);
}

/* All of `addrs` in one `nft` run. */
void	tpp_quic_block(const t_dns_addr *addrs, size_t n)
{
	char	script[DNS_MAX_ADDRS * 512];
	char	text[INET6_ADDRSTRLEN];
	size_t	len;
	size_t	i;

	len = 0;
	i = 0;
	while (i < n && i < DNS_MAX_ADDRS)
	{
		if (inet_ntop(addrs[i].family == 6 ? AF_INET6 : AF_INET,
				addrs[i].addr, text, sizeof(text)) != NULL)
			len += tp_nft_quic_block(script + len, sizeof(script) - len,
					addrs[i].family, text);
		i++;
	}
	if (len > 0)
		nft_run(script, len, 1);
}

void	tpp_quic_flush(void)
{
	char	buf[256];
	int		len;

	len = snprintf(buf, sizeof(buf), "flush set inet %s quic_block4\n"
			"flush set inet %s quic_block6\n", TP_NFT_TABLE, TP_NFT_TABLE);
	if (len > 0)
		nft_run(buf, (size_t)len, 1);
}

int	tpp_listen_wildcard(void)
{
	return (0);
}

int	tpp_original_dst(int client_fd, int family, struct sockaddr_storage *out,
	socklen_t *out_len)
{
	int					rc;
	struct sockaddr_in	*v4;
	struct sockaddr_in6	*v6;

	*out_len = sizeof(*out);
	memset(out, 0, sizeof(*out));
	if (family == AF_INET6)
		rc = getsockopt(client_fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, out,
				out_len);
	else
		rc = getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, out, out_len);
	if (rc < 0)
		return (-1);
	/* Anything addressed to loopback — including a direct connection to
	 * our own listener, which "recovers" itself — was not redirected
	 * by our rule: refuse rather than loop. */
	if (out->ss_family == AF_INET)
	{
		v4 = (struct sockaddr_in *)out;
		if ((ntohl(v4->sin_addr.s_addr) >> 24) == 127)
			return (-1);
		*out_len = sizeof(*v4);
	}
	else if (out->ss_family == AF_INET6)
	{
		v6 = (struct sockaddr_in6 *)out;
		if (IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr)
			|| IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr))
			return (-1);
		*out_len = sizeof(*v6);
	}
	else
		return (-1);
	return (0);
}

int	tpp_dns_peer_ok(const struct sockaddr *peer, socklen_t len, int tcp)
{
	/* the forwarder only listens on loopback */
	(void)peer;
	(void)len;
	(void)tcp;
	return (1);
}

int	tpp_prepare_socket(int fd, int family)
{
	int	mark;

	(void)family;
	mark = TP_SOCKET_MARK;
	/* an unmarked socket would be redirected straight back to us */
	return (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0
		? -1 : 0);
}

int	tpp_netwatch_fd(void)
{
	return (g_netlink);
}

int	tpp_netwatch_drain(void)
{
	char	buf[8192];

	if (g_netlink < 0)
		return (0);
	while (recv(g_netlink, buf, sizeof(buf), 0) > 0)
		;
	return (1);
}

uint64_t	tpp_network_fingerprint(void)
{
	return (netfingerprint_current());
}

const char	*tpp_conflict(void)
{
	static const char	*probe = "list table ip dpibypass\n";

	if (nft_run(probe, strlen(probe), 1) == 0)
		return ("dpi-bypass table active");
	return (NULL);
}

int	tpp_dns_original(int fd, const struct sockaddr *peer, socklen_t peer_len,
	int tcp, struct sockaddr_storage *out, socklen_t *out_len)
{
	(void)fd;
	(void)peer;
	(void)peer_len;
	(void)tcp;
	(void)out;
	(void)out_len;
	return (-1);
}

void	tpp_status_extra(char *out, size_t out_size)
{
	if (out_size > 0)
		out[0] = '\0';
}

const char	*tpp_name(void)
{
	return ("nftables");
}
