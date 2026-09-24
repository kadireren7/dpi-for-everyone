#define _GNU_SOURCE
#include "tp.h"
#include "tp_sys.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

/* Feeds `text` to `nft -f -`. Fixed argv, no shell; the text is built
 * only from constants, an int port and inet_ntop() output. stdout/
 * stderr are discarded unless `quiet` is 0. Returns 0 if nft exited 0. */
int	tp_nft_run(const char *text, size_t len, int quiet)
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

/* Whether the installed table redirects DNS (the heartbeat re-arms
 * alive_dns only then). Set by the main thread only. */
static int	g_dns;

int	tp_nft_install(int port, int ipv6, int dns_port)
{
	char	buf[3072];
	size_t	len;

	len = tp_nft_ruleset(buf, sizeof(buf), port, ipv6, dns_port);
	if (len == 0 || tp_nft_run(buf, len, 0) != 0)
		return (-1);
	g_dns = (dns_port > 0);
	return (tp_nft_refresh());
}

int	tp_nft_refresh(void)
{
	char	buf[512];
	size_t	len;

	len = tp_nft_heartbeat(buf, sizeof(buf), g_dns);
	if (len == 0)
		return (-1);
	return (tp_nft_run(buf, len, 1));
}

void	tp_nft_remove(void)
{
	char	buf[128];
	int		len;

	len = snprintf(buf, sizeof(buf), "table inet %s {}\ndelete table inet %s\n",
			TP_NFT_TABLE, TP_NFT_TABLE);
	if (len > 0)
		tp_nft_run(buf, (size_t)len, 1);
}

void	tp_nft_flush_quic(void)
{
	char	buf[256];
	int		len;

	len = snprintf(buf, sizeof(buf), "flush set inet %s quic_block4\n"
			"flush set inet %s quic_block6\n", TP_NFT_TABLE, TP_NFT_TABLE);
	if (len > 0)
		tp_nft_run(buf, (size_t)len, 1);
}

int	tp_nft_add_quic(int family, const char *addr)
{
	char	buf[512];
	size_t	len;

	len = tp_nft_quic_block(buf, sizeof(buf), family, addr);
	if (len == 0)
		return (-1);
	return (tp_nft_run(buf, len, 1));
}
