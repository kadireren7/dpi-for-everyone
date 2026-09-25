#define _GNU_SOURCE
#include "tpd.h"
#include "compat.h"
#include "tp_platform.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Local DNS forwarder. nftables redirects every outgoing UDP/TCP 53
 * query (tp.h, tp_nft_ruleset) here; each one is sent on unchanged
 * through the trusted resolver (DoH first, see dns_doh.h) and its
 * answer returned. Applications therefore get real addresses for
 * blocked names whatever resolver the system or the router is set
 * to — the precondition for everything conn.c does.
 *
 * For a name on the known-blocked list (tp_host_listed), the answer's
 * addresses go into the QUIC-reject set *before* the answer is sent,
 * so the application's first QUIC attempt is already refused and it
 * uses TCP, which we can bypass.
 *
 * No cache: the system stub resolver in front of us caches. If no
 * server answers, the client gets SERVFAIL (and retries). Queries the
 * platform layer did not redirect to us are ignored (tpp_dns_peer_ok;
 * matters where the listener is not loopback-only).
 *
 * Where the platform can tell which server a query was really sent to
 * (tpp_dns_original; macOS), that server — normally the router — is
 * still used for what only it can answer, never for a known-blocked
 * name:
 *   - local names (dns_name_is_local: "nas", "printer.lan", private
 *     reverse lookups) go only to it, never to a public resolver;
 *   - a name the trusted resolvers call nonexistent (NXDOMAIN) is
 *     asked there too (LAN names, a VPN's internal zones);
 *   - while every trusted resolver is failing (e.g. a captive portal
 *     before login), it is asked first, so the network keeps working
 *     (fail-open for DNS).
 * ============================================================ */

#define FWD_MAX_INFLIGHT 128
#define FWD_TCP_IDLE_MS 10000
#define FWD_MSG_MAX 65535
#define FWD_STACK_SIZE (128 * 1024)
#define ORIGINAL_TIMEOUT_MS 2000

/* The server a query was really sent to, when the platform knows. */
typedef struct s_orig
{
	struct sockaddr_storage	addr;
	socklen_t				len;
}	t_orig;

typedef struct s_udp_job
{
	int						fd;
	struct sockaddr_storage	peer;
	socklen_t				peer_len;
	size_t					len;
	uint8_t					query[4096];
}	t_udp_job;

static pthread_mutex_t	g_fwd_lock = PTHREAD_MUTEX_INITIALIZER;
static int				g_inflight;

static int	take_slot(void)
{
	int	ok;

	pthread_mutex_lock(&g_fwd_lock);
	ok = (g_inflight < FWD_MAX_INFLIGHT);
	if (ok)
		g_inflight++;
	pthread_mutex_unlock(&g_fwd_lock);
	return (ok);
}

static void	give_slot(void)
{
	pthread_mutex_lock(&g_fwd_lock);
	g_inflight--;
	pthread_mutex_unlock(&g_fwd_lock);
}

static void	count(int ok)
{
	pthread_mutex_lock(&g_tpd.lock);
	g_tpd.stats.dns_queries++;
	if (!ok)
		g_tpd.stats.dns_failures++;
	pthread_mutex_unlock(&g_tpd.lock);
}

/* Addresses of a known-blocked name: QUIC off before the answer goes
 * out. */
static void	note_answer(const uint8_t *reply, size_t len, const char *name,
	uint16_t qtype)
{
	t_dns_answer	ans;

	if ((qtype != DNS_QTYPE_A && qtype != DNS_QTYPE_AAAA)
		|| !tp_host_listed(name) || len < 2)
		return ;
	if (dns_parse_response(reply, len, (uint16_t)(reply[0] << 8 | reply[1]),
			name, qtype, &ans) == DNS_OK)
		tpd_quic_block_answer(&ans);
}

/* The client's query, unchanged, to the server it was meant for
 * (plain UDP from one of our own sockets, so it isn't intercepted). */
static long	ask_original(const t_orig *orig, const uint8_t *query,
	size_t qlen, uint8_t *reply, size_t reply_size)
{
	t_dns_udp_servers	one;
	long				n;

	memset(&one, 0, sizeof(one));
	if (orig->len > sizeof(one.addrs[0]))
		return (-1);
	memcpy(one.addrs[0], &orig->addr, orig->len);
	one.addr_lens[0] = (unsigned int)orig->len;
	one.count = 1;
	one.so_mark = TP_SOCKET_MARK;
	n = dns_udp_transport(0, query, qlen, reply, reply_size,
			ORIGINAL_TIMEOUT_MS, &one);
	if (n < 12 || reply[0] != query[0] || reply[1] != query[1]
		|| dns_reply_rcode(reply, (size_t)n) < 0)
		return (-1);
	return (n);
}

/* Trusted resolvers, with the network's own resolver (when known) for
 * what only it can answer — see the top of this file. */
static long	resolve(const uint8_t *query, size_t qlen, uint8_t *reply,
	size_t reply_size, const char *name, const t_orig *orig)
{
	uint8_t	*alt;
	long	n;
	long	m;

	if (orig != NULL && dns_name_is_local(name))
	{
		tpd_debug("[dns] %s: local name, asked the network's resolver", name);
		return (ask_original(orig, query, qlen, reply, reply_size));
	}
	if (orig != NULL && tp_host_listed(name))
		orig = NULL;
	if (orig != NULL && !dns_resolver_healthy(g_tpd.dns, tpd_now()))
	{
		n = ask_original(orig, query, qlen, reply, reply_size);
		if (n > 0)
		{
			tpd_debug("[dns] %s: trusted resolvers unreachable, answered by "
				"the network's resolver", name);
			return (n);
		}
	}
	n = dns_exchange(g_tpd.dns, query, qlen, reply, reply_size, tpd_now());
	if (orig == NULL || (n > 0 && dns_reply_rcode(reply, (size_t)n) != 3))
		return (n);
	alt = malloc(reply_size);
	if (alt == NULL)
		return (n);
	m = ask_original(orig, query, qlen, alt, reply_size);
	if (m > 0 && (n <= 0 || (dns_reply_rcode(alt, (size_t)m) == 0
				&& dns_reply_answer_count(alt, (size_t)m) > 0)))
	{
		tpd_debug("[dns] %s: %s; answered by the network's resolver", name,
			n > 0 ? "not in public DNS" : "trusted resolvers failed");
		memcpy(reply, alt, (size_t)m);
		n = m;
	}
	free(alt);
	return (n);
}

/* Answers one query into `reply` (never empty for a well-formed
 * query); `max` is what the client can take (UDP payload size). */
static size_t	answer(const uint8_t *query, size_t qlen, uint8_t *reply,
	size_t reply_size, int udp, const t_orig *orig)
{
	char		name[DNS_NAME_MAX];
	uint16_t	qtype;
	uint16_t	udp_size;
	long		n;

	if (dns_query_info(query, qlen, name, sizeof(name), &qtype, &udp_size)
		!= 0)
		return (0);
	n = resolve(query, qlen, reply, reply_size, name, orig);
	count(n > 0);
	if (n <= 0)
	{
		tpd_debug("[dns] %s: no resolver answered", name);
		return (dns_servfail_reply(query, qlen, reply, reply_size));
	}
	note_answer(reply, (size_t)n, name, qtype);
	if (udp && (size_t)n > udp_size)
		return (dns_truncated_reply(query, qlen, reply, reply_size));
	return ((size_t)n);
}

/* ---- UDP ---- */

static void	*udp_worker(void *p)
{
	t_udp_job	*job;
	uint8_t		*reply;
	size_t		n;
	t_orig		orig;
	int			known;

	job = p;
	reply = malloc(FWD_MSG_MAX);
	if (reply != NULL)
	{
		known = (tpp_dns_original(job->fd, (struct sockaddr *)&job->peer,
					job->peer_len, 0, &orig.addr, &orig.len) == 0);
		n = answer(job->query, job->len, reply, FWD_MSG_MAX, 1,
				known ? &orig : NULL);
		if (n > 0)
			sendto(job->fd, (const char *)reply, (int)n, 0,
				(struct sockaddr *)&job->peer, job->peer_len);
		free(reply);
	}
	free(job);
	give_slot();
	return (NULL);
}

static void	*udp_loop(void *p)
{
	int				fd;
	t_udp_job		*job;
	ssize_t			n;
	pthread_t		tid;
	pthread_attr_t	attr;

	fd = (int)(intptr_t)p;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, FWD_STACK_SIZE);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	while (1)
	{
		job = malloc(sizeof(*job));
		if (job == NULL)
		{
			compat_sleep_ms(10);
			continue ;
		}
		job->fd = fd;
		job->peer_len = sizeof(job->peer);
		n = recvfrom(fd, (char *)job->query, sizeof(job->query), 0,
				(struct sockaddr *)&job->peer, &job->peer_len);
		if (n < 12 || !tpp_dns_peer_ok((struct sockaddr *)&job->peer,
				job->peer_len, 0) || !take_slot())
		{
			/* dropped: the client's own retry timer handles it */
			free(job);
			continue ;
		}
		job->len = (size_t)n;
		if (pthread_create(&tid, &attr, udp_worker, job) != 0)
		{
			free(job);
			give_slot();
		}
	}
	return (NULL);
}

/* ---- TCP ---- */

static int	read_full(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
	size_t	have;
	ssize_t	n;

	have = 0;
	while (have < len)
	{
		if (compat_wait(fd, POLLIN, timeout_ms) <= 0)
			return (-1);
		n = compat_recv(fd, buf + have, len - have);
		if (n < 0 && compat_interrupted())
			continue ;
		if (n <= 0)
			return (-1);
		have += (size_t)n;
	}
	return (0);
}

static int	write_full(int fd, const uint8_t *buf, size_t len)
{
	ssize_t	n;

	while (len > 0)
	{
		n = compat_send(fd, buf, len);
		if (n < 0 && compat_interrupted())
			continue ;
		if (n <= 0)
			return (-1);
		buf += n;
		len -= (size_t)n;
	}
	return (0);
}

static void	*tcp_worker(void *p)
{
	int		fd;
	uint8_t	*query;
	uint8_t	*reply;
	uint8_t	hdr[2];
	size_t	qlen;
	size_t	n;
	t_orig	orig;
	int		known;

	fd = (int)(intptr_t)p;
	known = (tpp_dns_original(fd, NULL, 0, 1, &orig.addr, &orig.len) == 0);
	query = malloc(FWD_MSG_MAX);
	reply = malloc(FWD_MSG_MAX + 2);
	while (query != NULL && reply != NULL
		&& read_full(fd, hdr, 2, FWD_TCP_IDLE_MS) == 0)
	{
		qlen = (size_t)(hdr[0] << 8 | hdr[1]);
		if (qlen < 12 || read_full(fd, query, qlen, FWD_TCP_IDLE_MS) != 0)
			break ;
		n = answer(query, qlen, reply + 2, FWD_MSG_MAX, 0,
				known ? &orig : NULL);
		if (n == 0)
			break ;
		reply[0] = (uint8_t)(n >> 8);
		reply[1] = (uint8_t)(n & 0xff);
		if (write_full(fd, reply, n + 2) != 0)
			break ;
	}
	free(query);
	free(reply);
	compat_close(fd);
	give_slot();
	return (NULL);
}

static void	*tcp_loop(void *p)
{
	int						lfd;
	int						fd;
	pthread_t				tid;
	pthread_attr_t			attr;
	struct sockaddr_storage	peer;
	socklen_t				peer_len;

	lfd = (int)(intptr_t)p;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, FWD_STACK_SIZE);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	while (1)
	{
		fd = tpd_accept(lfd);
		if (fd < 0)
		{
			if (!compat_interrupted())
				compat_sleep_ms(10);
			continue ;
		}
		peer_len = sizeof(peer);
		if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0
			|| !tpp_dns_peer_ok((struct sockaddr *)&peer, peer_len, 1)
			|| !take_slot())
		{
			compat_close(fd);
			continue ;
		}
		if (pthread_create(&tid, &attr, tcp_worker, (void *)(intptr_t)fd)
			!= 0)
		{
			compat_close(fd);
			give_slot();
		}
	}
	return (NULL);
}

/* ---- setup ---- */

static int	start_family(int family, int port)
{
	int			ufd;
	int			tfd;
	pthread_t	tid;

	ufd = tpd_listen(family, SOCK_DGRAM, port);
	tfd = tpd_listen(family, SOCK_STREAM, port);
	if (ufd < 0 || tfd < 0
		|| pthread_create(&tid, NULL, udp_loop, (void *)(intptr_t)ufd) != 0)
	{
		if (ufd >= 0)
			compat_close(ufd);
		if (tfd >= 0)
			compat_close(tfd);
		return (-1);
	}
	pthread_detach(tid);
	if (pthread_create(&tid, NULL, tcp_loop, (void *)(intptr_t)tfd) != 0)
	{
		compat_close(tfd);
		return (-1);
	}
	pthread_detach(tid);
	return (0);
}

int	tpd_dnsfwd_start(int port, int *ipv6)
{
	if (start_family(AF_INET, port) != 0)
		return (-1);
	if (*ipv6 && start_family(AF_INET6, port) != 0)
	{
		tpd_log("[dns] no IPv6 forwarder on port %d (%s); IPv6 is left alone",
			port, compat_sock_strerror());
		*ipv6 = 0;
	}
	return (0);
}
