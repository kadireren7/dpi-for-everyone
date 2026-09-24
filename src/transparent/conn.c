#define _GNU_SOURCE
#include "tpd.h"
#include "common.h"
#include "compat.h"
#include "packet.h"
#include "relay.h"
#include "tls_sni.h"
#include "tp_platform.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* How long a client may take to send its first bytes before we assume
 * a server-speaks-first protocol and just pass the connection on. */
#define FIRST_BYTES_WAIT_MS 1000
/* Overall budget for collecting a ClientHello split across writes. */
#define CLIENT_HELLO_WAIT_MS 2000

/* A connection DIRECT to the original address "ended suspiciously" —
 * worth an independent certificate check — when the client gave up
 * right after the server's first flight: it sent almost nothing after
 * its ClientHello and closed first, quickly. That is what a client
 * rejecting a certificate looks like from the outside (an alert, then
 * close). It is only a trigger: the verifier decides. */
#define SUSPICIOUS_MAX_UP_BYTES 100
#define SUSPICIOUS_MAX_SECONDS 15

typedef struct s_conn
{
	int						client_fd;
	int						family;
	struct sockaddr_storage	original;
	socklen_t				original_len;
	unsigned char			hello[BUFFER_SIZE];
	size_t					hello_len;
	char					host[TLS_SNI_HOST_MAX];
	t_tp_plan				plan;
	struct sockaddr_storage	trusted;
	socklen_t				trusted_len;
	unsigned char			reply[BUFFER_SIZE];
	size_t					reply_len;
	uint64_t				fp;
}	t_conn;

void	tpd_addr_str(const struct sockaddr_storage *ss, char *out,
	size_t out_size)
{
	const void	*a;

	if (ss->ss_family == AF_INET6)
		a = &((const struct sockaddr_in6 *)ss)->sin6_addr;
	else
		a = &((const struct sockaddr_in *)ss)->sin_addr;
	if (inet_ntop(ss->ss_family, a, out, (socklen_t)out_size) == NULL)
		snprintf(out, out_size, "?");
}

static int	get_original_dst(t_conn *c)
{
	return (tpp_original_dst(c->client_fd, c->family, &c->original,
			&c->original_len));
}

static int	wait_readable(int fd, int timeout_ms)
{
	return (compat_wait(fd, POLLIN, timeout_ms));
}

/* SNI of what has arrived so far; a ClientHello split over several
 * TLS records is parsed as its merged form (c->reply is free until
 * the first attempt, so it serves as scratch). */
static int	parse_hello(t_conn *c)
{
	ssize_t	merged;
	int		rc;
	size_t	i;

	merged = tls_coalesce_handshake_records(c->hello, c->hello_len,
			c->reply, sizeof(c->reply));
	if (merged > 0)
		rc = tls_parse_client_hello_sni(c->reply, (size_t)merged,
				c->host, sizeof(c->host));
	else
		rc = tls_parse_client_hello_sni(c->hello, c->hello_len, c->host,
				sizeof(c->host));
	/* a name that isn't a hostname is never keyed, cached or logged */
	i = 0;
	while (rc == PACKET_OK && c->host[i] != '\0')
	{
		if (!isalnum((unsigned char)c->host[i]) && c->host[i] != '.'
			&& c->host[i] != '-' && c->host[i] != '_')
			rc = PACKET_ERR_MALFORMED;
		i++;
	}
	return (rc);
}

/* Collects the client's first bytes: until a complete ClientHello
 * (SNI found, or definitely no SNI), the buffer is full, or time is
 * up. Returns the byte count (0 = client sent nothing in time). */
static size_t	read_client_hello(t_conn *c)
{
	ssize_t	merged;
	ssize_t	n;
	int64_t	deadline_ms;
	int		wait_ms;
	int		rc;

	c->host[0] = '\0';
	c->hello_len = 0;
	wait_ms = FIRST_BYTES_WAIT_MS;
	deadline_ms = tpd_now_ms() + CLIENT_HELLO_WAIT_MS;
	while (c->hello_len < sizeof(c->hello))
	{
		if (wait_readable(c->client_fd, wait_ms) <= 0)
			break ;
		n = compat_recv(c->client_fd, c->hello + c->hello_len,
				sizeof(c->hello) - c->hello_len);
		if (n < 0 && compat_interrupted())
			continue ;
		if (n <= 0)
			break ;
		c->hello_len += (size_t)n;
		rc = parse_hello(c);
		if (rc != PACKET_ERR_TRUNCATED)
		{
			if (rc != PACKET_OK)
				c->host[0] = '\0';
			break ;
		}
		wait_ms = (int)(deadline_ms - tpd_now_ms());
		if (wait_ms <= 0)
			break ;
	}
	/* from here on the ClientHello is one record: attempts re-frame
	 * (TLSREC) exactly as if the client had sent it whole */
	merged = tls_coalesce_handshake_records(c->hello, c->hello_len,
			c->reply, sizeof(c->reply));
	if (merged > 0)
	{
		memcpy(c->hello, c->reply, (size_t)merged);
		c->hello_len = (size_t)merged;
	}
	return (c->hello_len);
}

static int	addr_equal(const struct sockaddr_storage *ss, const t_dns_addr *a)
{
	if (ss->ss_family == AF_INET && a->family == 4)
		return (memcmp(&((const struct sockaddr_in *)ss)->sin_addr,
				a->addr, 4) == 0);
	if (ss->ss_family == AF_INET6 && a->family == 6)
		return (memcmp(&((const struct sockaddr_in6 *)ss)->sin6_addr,
				a->addr, 16) == 0);
	return (0);
}

/* Asks the trusted resolver for the host (same family as the original
 * connection) and sets plan.trust; on a mismatch, c->trusted is the
 * first trusted address. */
static void	resolve_trusted(t_conn *c)
{
	t_dns_answer	ans;
	t_dns_status	st;
	size_t			i;
	uint16_t		port;

	st = dns_resolve(g_tpd.dns, c->host,
			c->family == AF_INET6 ? DNS_QTYPE_AAAA : DNS_QTYPE_A,
			tpd_now(), &ans);
	if (st != DNS_OK || ans.count == 0)
	{
		c->plan.trust = TP_TRUST_NONE;
		tpd_debug("[dns] %s: %s", c->host, dns_status_name(st));
		return ;
	}
	i = 0;
	while (i < ans.count)
	{
		if (addr_equal(&c->original, &ans.addrs[i]))
		{
			c->plan.trust = TP_TRUST_MATCH;
			return ;
		}
		i++;
	}
	c->plan.trust = TP_TRUST_MISMATCH;
	memset(&c->trusted, 0, sizeof(c->trusted));
	if (c->original.ss_family == AF_INET6)
		port = ((struct sockaddr_in6 *)&c->original)->sin6_port;
	else
		port = ((struct sockaddr_in *)&c->original)->sin_port;
	if (ans.addrs[0].family == 6)
	{
		((struct sockaddr_in6 *)&c->trusted)->sin6_family = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)&c->trusted)->sin6_addr,
			ans.addrs[0].addr, 16);
		((struct sockaddr_in6 *)&c->trusted)->sin6_port = port;
		c->trusted_len = sizeof(struct sockaddr_in6);
	}
	else
	{
		((struct sockaddr_in *)&c->trusted)->sin_family = AF_INET;
		memcpy(&((struct sockaddr_in *)&c->trusted)->sin_addr,
			ans.addrs[0].addr, 4);
		((struct sockaddr_in *)&c->trusted)->sin_port = port;
		c->trusted_len = sizeof(struct sockaddr_in);
	}
}

static int	split_mode(t_strategy s)
{
	return (relay_split_for(s));
}

/* One attempt: connect, send the (possibly re-framed) ClientHello,
 * wait for the server's first bytes. On OK/ALERT *upstream_fd is the
 * live connection and c->reply holds what the server sent. */
static t_tp_result	attempt(t_conn *c, t_tp_step step, int timeout_ms,
	int *upstream_fd)
{
	const struct sockaddr_storage	*dst;
	socklen_t						dst_len;
	int								fd;
	ssize_t							n;

	*upstream_fd = -1;
	dst = &c->original;
	dst_len = c->original_len;
	if (step.target == TP_TARGET_TRUSTED)
	{
		dst = &c->trusted;
		dst_len = c->trusted_len;
	}
	fd = tpd_connect((const struct sockaddr *)dst, dst_len,
			TP_CONNECT_TIMEOUT_MS);
	if (fd < 0)
		return (TP_RES_CONNECT_FAIL);
	if (relay_send_first(fd, c->hello, c->hello_len,
			split_mode(step.strategy)) < 0)
	{
		compat_close(fd);
		return (TP_RES_RESET);
	}
	if (wait_readable(fd, timeout_ms) <= 0)
	{
		compat_close(fd);
		return (TP_RES_TIMEOUT);
	}
	do
		n = compat_recv(fd, c->reply, sizeof(c->reply));
	while (n < 0 && compat_interrupted());
	if (n <= 0)
	{
		compat_close(fd);
		return (n == 0 ? TP_RES_CLOSED : TP_RES_RESET);
	}
	c->reply_len = (size_t)n;
	*upstream_fd = fd;
	if (c->reply[0] == 0x16)
		return (TP_RES_OK);
	if (c->reply[0] == 0x15)
		return (TP_RES_ALERT);
	compat_close(fd);
	*upstream_fd = -1;
	return (TP_RES_NOT_TLS);
}

/* No hostname, host in cooldown, manual "pass": connect to the
 * original address and relay, with no attempt classification. */
static void	passthrough(t_conn *c)
{
	int	fd;

	fd = tpd_connect((const struct sockaddr *)&c->original,
			c->original_len, TP_CONNECT_TIMEOUT_MS);
	if (fd < 0)
		return ;
	if (c->hello_len == 0
		|| relay_send_all(fd, c->hello, c->hello_len) == 0)
		relay_pump(c->client_fd, fd, NULL);
	compat_close(fd);
}

static void	fill_plan(t_conn *c, int64_t now)
{
	t_strategy_chain	chain;
	t_tp_decision		*d;

	tp_plan_init(&c->plan);
	c->plan.has_host = (c->host[0] != '\0');
	if (!c->plan.has_host)
		return ;
	c->plan.listed = tp_host_listed(c->host);
	pthread_mutex_lock(&g_tpd.lock);
	c->fp = g_tpd.fp;
	c->plan.preferred = g_tpd.preferred;
	if (strategy_has_explicit_rule(&g_tpd.cfg, c->host, &chain))
	{
		c->plan.has_manual = 1;
		c->plan.manual = chain.actions[0];
	}
	d = tp_decision_lookup(&g_tpd.dec, c->host, c->fp,
			c->family == AF_INET6 ? 6 : 4, now);
	if (d != NULL)
	{
		c->plan.has_cached = 1;
		c->plan.cached = d->step;
	}
	c->plan.in_cooldown = tp_in_cooldown(&g_tpd.dec, c->host, now);
	c->plan.direct_bad = tp_direct_bad(&g_tpd.dec, c->host, c->fp,
			c->family == AF_INET6 ? 6 : 4, now);
	pthread_mutex_unlock(&g_tpd.lock);
}

static void	make_job(const t_conn *c, t_tpd_verify_kind kind, t_tp_step step,
	t_tpd_verify_job *job)
{
	memset(job, 0, sizeof(*job));
	job->kind = kind;
	snprintf(job->host, sizeof(job->host), "%s", c->host);
	job->family = (c->family == AF_INET6) ? 6 : 4;
	job->fp = c->fp;
	job->step = step;
	job->original = c->original;
	if (step.target == TP_TARGET_TRUSTED)
	{
		job->addr = c->trusted;
		job->addr_len = c->trusted_len;
	}
	else
	{
		job->addr = c->original;
		job->addr_len = c->original_len;
	}
}

static int	is_direct(t_tp_step s)
{
	return (s.target == TP_TARGET_ORIGINAL && s.strategy == STRATEGY_PASS);
}

/* The attempt that got an answer is now the connection: hand the
 * server's first bytes to the client and relay the rest. */
static void	commit(t_conn *c, t_tp_step step, int upstream_fd, int64_t started)
{
	t_relay_stats		rs;
	t_tpd_verify_job	job;
	t_tp_source			src;
	int					family;

	family = (c->family == AF_INET6) ? 6 : 4;
	src = tp_plan_source(&c->plan);
	pthread_mutex_lock(&g_tpd.lock);
	if (is_direct(step))
	{
		g_tpd.stats.direct++;
		if (src != TP_SRC_MANUAL)
			tp_decision_success(&g_tpd.dec, c->host, c->fp, family,
				tpd_now(), step);
	}
	else
	{
		g_tpd.stats.bypassed++;
		g_tpd.preferred = step.strategy;
	}
	pthread_mutex_unlock(&g_tpd.lock);
	/* this host only works bypassed: keep its QUIC (which carries the
	 * same SNI in the clear, and which we can't rewrite) off the wire
	 * right away, not only after the verifier confirmed the step */
	if (!is_direct(step))
		tpd_quic_block_sockaddr(&c->original);
	tpd_debug("[conn] %s: %s+%s (%s, attempt %zu)", c->host,
		tp_target_name(step.target), strategy_name(step.strategy),
		tp_source_name(src), c->plan.ntried);
	if (!is_direct(step) && src != TP_SRC_MANUAL && src != TP_SRC_CACHED)
	{
		make_job(c, TPD_VERIFY_CONFIRM, step, &job);
		tpd_verify_submit(&job);
	}
	if (relay_send_all(c->client_fd, c->reply, c->reply_len) == 0)
		relay_pump(c->client_fd, upstream_fd, &rs);
	else
		memset(&rs, 0, sizeof(rs));
	if (is_direct(step) && src != TP_SRC_MANUAL && rs.client_eof_first
		&& rs.up_bytes < SUSPICIOUS_MAX_UP_BYTES
		&& tpd_now() - started <= SUSPICIOUS_MAX_SECONDS)
	{
		make_job(c, TPD_VERIFY_DIRECT, step, &job);
		tpd_verify_submit(&job);
	}
}

static void	run_plan(t_conn *c)
{
	t_tp_step	step;
	int			timeout_ms;
	int			upstream_fd;
	t_tp_result	r;
	t_tp_next	next;
	int64_t		started;
	char		addr[INET6_ADDRSTRLEN];

	started = tpd_now();
	while (1)
	{
		next = tp_plan_next(&c->plan, &step, &timeout_ms);
		if (next == TP_NEXT_DONE)
			break ;
		if (next == TP_NEXT_NEED_DNS)
		{
			resolve_trusted(c);
			continue ;
		}
		r = attempt(c, step, timeout_ms, &upstream_fd);
		tp_plan_record(&c->plan, step, r);
		tpd_debug("[conn] %s: %s+%s -> %s", c->host,
			tp_target_name(step.target), strategy_name(step.strategy),
			tp_result_name(r));
		if (r == TP_RES_OK || r == TP_RES_ALERT)
		{
			commit(c, step, upstream_fd, started);
			compat_close(upstream_fd);
			return ;
		}
	}
	tpd_addr_str(&c->original, addr, sizeof(addr));
	pthread_mutex_lock(&g_tpd.lock);
	g_tpd.stats.failed++;
	if (!c->plan.has_manual)
		tp_decision_failure(&g_tpd.dec, c->host, c->fp,
			c->family == AF_INET6 ? 6 : 4, tpd_now());
	pthread_mutex_unlock(&g_tpd.lock);
	tpd_log("[fail] %s (%s): no attempt got a TLS answer (%zu tried, last: "
		"%s); retrying direct-only for %ds", c->host, addr,
		c->plan.ntried, c->plan.ntried
		? tp_result_name(c->plan.results[c->plan.ntried - 1]) : "none",
		TP_COOLDOWN_SECONDS);
}

void	tpd_handle_connection(int client_fd, int family)
{
	t_conn			conn;
	t_conn			*c;
	struct linger	lg;

	c = &conn;
	memset(c, 0, offsetof(t_conn, hello));
	c->client_fd = client_fd;
	c->family = family;
	if (get_original_dst(c) < 0)
	{
		compat_close(client_fd);
		return ;
	}
	pthread_mutex_lock(&g_tpd.lock);
	g_tpd.stats.flows_total++;
	g_tpd.stats.flows_active++;
	pthread_mutex_unlock(&g_tpd.lock);
	read_client_hello(c);
	fill_plan(c, tpd_now());
	if (!c->plan.has_host
		|| (c->plan.in_cooldown && !c->plan.listed)
		|| (c->plan.has_manual && c->plan.manual == STRATEGY_PASS))
	{
		pthread_mutex_lock(&g_tpd.lock);
		g_tpd.stats.passthrough++;
		pthread_mutex_unlock(&g_tpd.lock);
		passthrough(c);
	}
	else
		run_plan(c);
	if (c->plan.has_host && c->plan.ntried > 0
		&& c->plan.results[c->plan.ntried - 1] != TP_RES_OK
		&& c->plan.results[c->plan.ntried - 1] != TP_RES_ALERT)
	{
		/* every attempt failed: make the application see a reset,
		 * like the connection it would have had */
		lg.l_onoff = 1;
		lg.l_linger = 0;
		setsockopt(client_fd, SOL_SOCKET, SO_LINGER, (const char *)&lg,
			sizeof(lg));
	}
	compat_close(client_fd);
	pthread_mutex_lock(&g_tpd.lock);
	g_tpd.stats.flows_active--;
	pthread_mutex_unlock(&g_tpd.lock);
}
