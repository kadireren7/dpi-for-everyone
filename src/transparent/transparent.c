#define _GNU_SOURCE
#include "tpd.h"
#include "netfingerprint.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ============================================================
 * `dpi-proxy --mode transparent` (Linux): the SOCKS proxy's stream
 * core (relay.c) behind a loopback listener that nftables REDIRECTs
 * outgoing TCP/443 to. See tp.h for the decision model and
 * docs/transparent-mode.md for operation.
 *
 * Threads: this main loop (accept, heartbeat, network watch, status),
 * one detached thread per connection (conn.c, same model as
 * socks.c), and one verifier thread (verify.c).
 * ============================================================ */

#define CONN_STACK_SIZE (256 * 1024)
/* Debounce for bursts of routing/address events (Wi-Fi reconnect). */
#define NETCHANGE_SETTLE_MS 2000
/* Fallback network re-check when no netlink event arrives. */
#define NETCHECK_INTERVAL_S 60

t_tpd							g_tpd;
static volatile sig_atomic_t	g_stop;
static volatile sig_atomic_t	g_reload;

/* ---- small utilities ---- */

int64_t	tpd_now(void)
{
	return ((int64_t)time(NULL));
}

int64_t	tpd_now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void	vlog(const char *fmt, va_list ap)
{
	char	line[1024];

	vsnprintf(line, sizeof(line), fmt, ap);
	fprintf(stderr, "%s\n", line);
}

void	tpd_log(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vlog(fmt, ap);
	va_end(ap);
}

void	tpd_debug(const char *fmt, ...)
{
	va_list	ap;

	if (!g_tpd.opt.debug)
		return ;
	va_start(ap, fmt);
	vlog(fmt, ap);
	va_end(ap);
}

static const char	*env_or(const char *name, const char *fallback)
{
	const char	*v;

	v = getenv(name);
	if (v != NULL && v[0] != '\0')
		return (v);
	return (fallback);
}

void	tp_options_default(t_tp_options *opt)
{
	const char	*v;

	memset(opt, 0, sizeof(*opt));
	opt->port = TP_DEFAULT_PORT;
	v = getenv("DPI_PROXY_TP_PORT");
	if (v != NULL && atoi(v) > 0 && atoi(v) < 65536)
		opt->port = atoi(v);
	v = getenv("DPI_PROXY_LOG_LEVEL");
	opt->debug = (v != NULL && strcmp(v, "debug") == 0);
	opt->strategy_conf = env_or("DPI_PROXY_STRATEGY_CONF",
			"/etc/dpi-proxy/strategy.conf");
	opt->decisions_file = env_or("DPI_PROXY_TP_DECISIONS",
			"/var/lib/dpi-proxy/tp-decisions.conf");
	opt->status_file = env_or("DPI_PROXY_TP_STATUS",
			"/run/dpi-proxy/transparent.status");
	opt->dns_servers = env_or("DPI_PROXY_DNS_SERVERS", DNS_DEFAULT_SERVERS);
	/* DPI_PROXY_TP_DNS: forwarder port, or 0/off to leave DNS alone */
	opt->dns_port = TP_DEFAULT_DNS_PORT;
	v = getenv("DPI_PROXY_TP_DNS");
	if (v != NULL && (strcmp(v, "off") == 0 || strcmp(v, "0") == 0))
		opt->dns_port = 0;
	else if (v != NULL && atoi(v) > 0 && atoi(v) < 65536)
		opt->dns_port = atoi(v);
	v = getenv("DPI_PROXY_DOH");
	opt->doh = !(v != NULL && (strcmp(v, "off") == 0 || strcmp(v, "0") == 0));
}

/* ---- files ---- */

static char	*read_file(const char *path, size_t *len)
{
	FILE	*f;
	char	*buf;
	long	size;

	*len = 0;
	f = fopen(path, "r");
	if (f == NULL)
		return (NULL);
	if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0
		|| size > 4 * 1024 * 1024 || fseek(f, 0, SEEK_SET) != 0)
	{
		fclose(f);
		return (NULL);
	}
	buf = malloc((size_t)size + 1);
	if (buf != NULL)
	{
		*len = fread(buf, 1, (size_t)size, f);
		buf[*len] = '\0';
	}
	fclose(f);
	return (buf);
}

/* Writes via a temporary file + rename, so a reader never sees a
 * half-written file. */
static int	write_file_atomic(const char *path, const char *data, size_t len)
{
	char	tmp[4096];
	FILE	*f;
	size_t	w;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return (-1);
	f = fopen(tmp, "w");
	if (f == NULL)
		return (-1);
	w = fwrite(data, 1, len, f);
	if (fclose(f) != 0 || w != len || rename(tmp, path) != 0)
	{
		unlink(tmp);
		return (-1);
	}
	return (0);
}

static void	load_strategy_conf(void)
{
	char				*text;
	size_t				len;
	t_strategy_config	cfg;

	strategy_config_init(&cfg);
	text = read_file(g_tpd.opt.strategy_conf, &len);
	if (text != NULL)
	{
		strategy_config_parse(&cfg, text, len);
		free(text);
	}
	pthread_mutex_lock(&g_tpd.lock);
	g_tpd.cfg = cfg;
	pthread_mutex_unlock(&g_tpd.lock);
	tpd_log("[config] %zu manual rule(s) from %s", cfg.rule_count,
		g_tpd.opt.strategy_conf);
}

static void	load_decisions(void)
{
	char	*text;
	size_t	len;
	size_t	skipped;

	text = read_file(g_tpd.opt.decisions_file, &len);
	if (text == NULL)
		return ;
	skipped = tp_decisions_parse(&g_tpd.dec, text, len);
	free(text);
	tpd_log("[decisions] loaded %zu from %s (%zu malformed line(s) skipped)",
		g_tpd.dec.count, g_tpd.opt.decisions_file, skipped);
}

static void	save_decisions(void)
{
	char	*buf;
	size_t	size;
	size_t	len;

	pthread_mutex_lock(&g_tpd.lock);
	if (!g_tpd.dec.dirty)
	{
		pthread_mutex_unlock(&g_tpd.lock);
		return ;
	}
	size = 128 + g_tpd.dec.count * (STRATEGY_DOMAIN_MAX + 96);
	buf = malloc(size);
	len = 0;
	if (buf != NULL)
		len = tp_decisions_serialize(&g_tpd.dec, buf, size);
	if (len > 0)
		g_tpd.dec.dirty = 0;
	pthread_mutex_unlock(&g_tpd.lock);
	if (len > 0 && write_file_atomic(g_tpd.opt.decisions_file, buf, len) != 0)
		tpd_log("[decisions] could not write %s: %s",
			g_tpd.opt.decisions_file, strerror(errno));
	free(buf);
}

static void	write_status(const char *engine)
{
	char		buf[2048];
	int			n;
	t_tpd_stats	s;
	uint64_t	fp;
	size_t		ndec;
	int			dns_ok;
	char		learned[sizeof(g_tpd.last_learned)];

	pthread_mutex_lock(&g_tpd.lock);
	s = g_tpd.stats;
	fp = g_tpd.fp;
	ndec = g_tpd.dec.count;
	memcpy(learned, g_tpd.last_learned, sizeof(learned));
	pthread_mutex_unlock(&g_tpd.lock);
	dns_ok = dns_resolver_healthy(g_tpd.dns, tpd_now());
	n = snprintf(buf, sizeof(buf),
			"engine: %s\nmode: transparent\npid: %d\nstarted: %" PRId64 "\n"
			"updated: %" PRId64 "\nport: %d\ndns: %s\nnetwork: %016" PRIx64 "\n"
			"flows: %lu\nactive: %lu\npassthrough: %lu\ndirect: %lu\n"
			"bypassed: %lu\nfailures: %lu\nverified_ok: %lu\n"
			"verified_bad: %lu\ndecisions: %zu\nlast_learned: %s\n"
			"dns_intercept: %s\ndns_queries: %lu\ndns_failures: %lu\n"
			"conflict: %s\n",
			engine, (int)getpid(), g_tpd.started_at, tpd_now(),
			g_tpd.opt.port, dns_ok ? "healthy" : "degraded", fp,
			s.flows_total, s.flows_active, s.passthrough, s.direct,
			s.bypassed, s.failed, s.verified_ok, s.verified_bad, ndec,
			learned[0] ? learned : "-",
			g_tpd.dns_intercept ? (g_tpd.doh ? "doh" : "plain") : "off",
			s.dns_queries, s.dns_failures,
			g_tpd.conflict ? "dpi-bypass table active" : "none");
	if (n > 0 && (size_t)n < sizeof(buf))
		write_file_atomic(g_tpd.opt.status_file, buf, (size_t)n);
}

/* ---- DNS ---- */

static void	dns_lock_fn(void *ctx, int lock)
{
	if (lock)
		pthread_mutex_lock((pthread_mutex_t *)ctx);
	else
		pthread_mutex_unlock((pthread_mutex_t *)ctx);
}

/* The trusted resolver: DoH servers first, the plain-UDP ones only
 * after every DoH server failed (see dns_doh.h). Used both by the
 * ladder (TP_NEXT_NEED_DNS) and by the DNS forwarder. */
static int	init_dns(void)
{
	size_t	n;

	n = dns_udp_servers_parse(&g_tpd.dns_servers, g_tpd.opt.dns_servers,
			TP_SOCKET_MARK);
	if (g_tpd.opt.doh)
	{
		g_tpd.doh = dns_doh_new(env_or("DPI_PROXY_DOH_SERVERS",
					DNS_DOH_DEFAULT_SERVERS), TP_SOCKET_MARK,
				n > 0 ? &g_tpd.dns_servers : NULL);
		if (g_tpd.doh == NULL)
			tpd_log("[dns] DNS-over-HTTPS unavailable (no usable server or "
				"TLS setup failed); plain DNS only");
	}
	if (n == 0 && g_tpd.doh == NULL)
	{
		tpd_log("[dns] no usable resolver in \"%s\"", g_tpd.opt.dns_servers);
		return (-1);
	}
	g_tpd.dns = calloc(1, sizeof(*g_tpd.dns));
	if (g_tpd.dns == NULL)
		return (-1);
	if (g_tpd.doh != NULL)
		dns_resolver_init(g_tpd.dns, dns_doh_total(g_tpd.doh),
			dns_doh_transport, g_tpd.doh, 2500,
			(uint16_t)(getpid() ^ tpd_now()));
	else
		dns_resolver_init(g_tpd.dns, n, dns_udp_transport,
			&g_tpd.dns_servers, 1500, (uint16_t)(getpid() ^ tpd_now()));
	pthread_mutex_init(&g_tpd.dns_lock, NULL);
	g_tpd.dns->lock = dns_lock_fn;
	g_tpd.dns->lock_ctx = &g_tpd.dns_lock;
	if (g_tpd.doh != NULL)
		tpd_log("[dns] trusted resolvers: DoH %s, then plain %s",
			env_or("DPI_PROXY_DOH_SERVERS", DNS_DOH_DEFAULT_SERVERS),
			n > 0 ? g_tpd.opt.dns_servers : "(none)");
	else
		tpd_log("[dns] trusted resolvers: %s (plain DNS)",
			g_tpd.opt.dns_servers);
	return (0);
}

/* Another transparent DPI tool (the reference dpi-bypass daemon, or
 * our own packet mode) intercepting the same traffic makes both of
 * them fail in confusing ways — e.g. our upstream connections get
 * redirected into the other proxy, which does not exempt our mark.
 * We can't fix that from here; say so loudly. */
static void	check_conflicts(void)
{
	static const char	*probe = "list table ip dpibypass\n";
	int					seen;

	seen = (tp_nft_run(probe, strlen(probe), 1) == 0);
	if (seen && !g_tpd.conflict)
		tpd_log("[conflict] WARNING: the dpi-bypass service's nftables "
			"table (ip dpibypass) is active. Two transparent interceptors "
			"proxy each other's traffic and break connections: stop one "
			"(`sudo systemctl stop dpi-bypass`).");
	else if (!seen && g_tpd.conflict)
		tpd_log("[conflict] dpi-bypass's table is gone; no conflict");
	g_tpd.conflict = seen;
}

/* ---- network watch ---- */

static int	open_netlink(void)
{
	int					fd;
	struct sockaddr_nl	sa;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
			NETLINK_ROUTE);
	if (fd < 0)
		return (-1);
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
		| RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
		close(fd);
		return (-1);
	}
	return (fd);
}

static void	drain(int fd)
{
	char	buf[8192];

	while (recv(fd, buf, sizeof(buf), 0) > 0)
		;
}

/* Recomputes the network fingerprint; on a change, forgets what was
 * specific to the old network (DNS answers, cooldowns, direct-bad
 * marks, QUIC blocks). Learned decisions are keyed by fingerprint,
 * so switching back later finds them again. */
static void	check_network(void)
{
	uint64_t	fp;
	uint64_t	old;

	fp = netfingerprint_current();
	pthread_mutex_lock(&g_tpd.lock);
	old = g_tpd.fp;
	if (fp != old)
	{
		g_tpd.fp = fp;
		g_tpd.preferred = STRATEGY_PASS;
		tp_decisions_network_changed(&g_tpd.dec);
	}
	pthread_mutex_unlock(&g_tpd.lock);
	if (fp == old)
		return ;
	dns_cache_flush(g_tpd.dns);
	if (g_tpd.doh != NULL)
		dns_doh_drop_idle(g_tpd.doh);
	tp_nft_flush_quic();
	tpd_quic_forget();
	tpd_log("[network] profile %016" PRIx64 " -> %016" PRIx64 "%s", old, fp,
		fp == NETFP_UNKNOWN ? " (no default route: nothing is learned "
		"until one appears)" : "");
}

/* ---- listeners ---- */

static int	listen_on(int family, int port)
{
	int					fd;
	int					one;
	struct sockaddr_in	v4;
	struct sockaddr_in6	v6;
	int					rc;

	fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);
	one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (family == AF_INET6)
	{
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		memset(&v6, 0, sizeof(v6));
		v6.sin6_family = AF_INET6;
		v6.sin6_addr = in6addr_loopback;
		v6.sin6_port = htons((uint16_t)port);
		rc = bind(fd, (struct sockaddr *)&v6, sizeof(v6));
	}
	else
	{
		memset(&v4, 0, sizeof(v4));
		v4.sin_family = AF_INET;
		v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		v4.sin_port = htons((uint16_t)port);
		rc = bind(fd, (struct sockaddr *)&v4, sizeof(v4));
	}
	if (rc < 0 || listen(fd, 512) < 0)
	{
		close(fd);
		return (-1);
	}
	return (fd);
}

typedef struct s_conn_arg
{
	int	fd;
	int	family;
}	t_conn_arg;

static void	*conn_thread(void *p)
{
	t_conn_arg	arg;

	arg = *(t_conn_arg *)p;
	free(p);
	tpd_handle_connection(arg.fd, arg.family);
	return (NULL);
}

static void	accept_one(int listen_fd, int family, pthread_attr_t *attr)
{
	int			fd;
	t_conn_arg	*arg;
	pthread_t	tid;

	fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
	if (fd < 0)
		return ;
	arg = malloc(sizeof(*arg));
	if (arg == NULL)
	{
		close(fd);
		return ;
	}
	arg->fd = fd;
	arg->family = family;
	if (pthread_create(&tid, attr, conn_thread, arg) != 0)
	{
		tpd_log("[conn] could not start a thread: %s", strerror(errno));
		close(fd);
		free(arg);
	}
}

/* ---- main loop ---- */

static void	on_signal(int sig)
{
	if (sig == SIGHUP)
		g_reload = 1;
	else
		g_stop = 1;
}

static void	install_signals(void)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
}

static void	heartbeat(void)
{
	/* the refresh fails if our table vanished (e.g. someone ran
	 * `nft flush ruleset`): put it back */
	if (tp_nft_refresh() != 0)
	{
		tpd_log("[nft] table %s missing or broken, reinstalling",
			TP_NFT_TABLE);
		if (tp_nft_install(g_tpd.opt.port, g_tpd.ipv6,
				g_tpd.dns_intercept ? g_tpd.opt.dns_port : 0) != 0)
			tpd_log("[nft] reinstall failed; traffic is NOT intercepted "
				"(fail-open)");
	}
	save_decisions();
	write_status("running");
}

static void	main_loop(int lfd4, int lfd6, int nlfd)
{
	struct pollfd	pfd[3];
	pthread_attr_t	attr;
	int64_t			next_beat;
	int64_t			net_due;
	int64_t			next_netcheck;
	int64_t			now;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, CONN_STACK_SIZE);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	next_beat = tpd_now_ms() + TP_HEARTBEAT_S * 1000;
	next_netcheck = tpd_now_ms() + NETCHECK_INTERVAL_S * 1000;
	net_due = 0;
	while (!g_stop)
	{
		pfd[0].fd = lfd4;
		pfd[1].fd = lfd6;
		pfd[2].fd = nlfd;
		pfd[0].events = POLLIN;
		pfd[1].events = POLLIN;
		pfd[2].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].revents = 0;
		pfd[2].revents = 0;
		if (poll(pfd, 3, 1000) < 0 && errno != EINTR)
			break ;
		if (pfd[0].revents & POLLIN)
			accept_one(lfd4, AF_INET, &attr);
		if (pfd[1].revents & POLLIN)
			accept_one(lfd6, AF_INET6, &attr);
		now = tpd_now_ms();
		if (pfd[2].revents & POLLIN)
		{
			drain(nlfd);
			net_due = now + NETCHANGE_SETTLE_MS;
		}
		if ((net_due != 0 && now >= net_due) || now >= next_netcheck)
		{
			net_due = 0;
			next_netcheck = now + NETCHECK_INTERVAL_S * 1000;
			check_network();
			check_conflicts();
		}
		if (g_reload)
		{
			g_reload = 0;
			load_strategy_conf();
		}
		if (now >= next_beat)
		{
			next_beat = now + TP_HEARTBEAT_S * 1000;
			heartbeat();
		}
	}
	pthread_attr_destroy(&attr);
}

int	run_transparent_server(const t_tp_options *opt)
{
	int	lfd4;
	int	lfd6;
	int	nlfd;

	memset(&g_tpd, 0, sizeof(g_tpd));
	g_tpd.opt = *opt;
	g_tpd.started_at = tpd_now();
	pthread_mutex_init(&g_tpd.lock, NULL);
	tp_decisions_init(&g_tpd.dec);
	install_signals();
	if (init_dns() != 0)
		return (-1);
	load_strategy_conf();
	g_tpd.fp = netfingerprint_current();
	load_decisions();
	tpd_log("[network] profile %016" PRIx64, g_tpd.fp);
	/* listeners first: the redirect must never point at nothing */
	lfd4 = listen_on(AF_INET, opt->port);
	if (lfd4 < 0)
	{
		tpd_log("cannot listen on 127.0.0.1:%d: %s", opt->port,
			strerror(errno));
		return (-1);
	}
	lfd6 = listen_on(AF_INET6, opt->port);
	if (lfd6 < 0)
		tpd_log("note: no [::1]:%d listener (%s); IPv6 is left alone",
			opt->port, strerror(errno));
	g_tpd.ipv6 = (lfd6 >= 0);
	if (opt->dns_port > 0)
	{
		if (tpd_dnsfwd_start(opt->dns_port, &g_tpd.ipv6) == 0)
			g_tpd.dns_intercept = 1;
		else
			tpd_log("[dns] cannot listen on 127.0.0.1:%d (%s); DNS is NOT "
				"intercepted — blocked names may resolve to block pages",
				opt->dns_port, strerror(errno));
	}
	nlfd = open_netlink();
	check_conflicts();
	if (tpd_verify_start() != 0 || tp_nft_install(opt->port, g_tpd.ipv6,
			g_tpd.dns_intercept ? opt->dns_port : 0) != 0)
	{
		tpd_log("cannot install nftables table %s (needs CAP_NET_ADMIN "
			"and the nft binary)", TP_NFT_TABLE);
		tp_nft_remove();
		close(lfd4);
		if (lfd6 >= 0)
			close(lfd6);
		return (-1);
	}
	tpd_log("transparent mode: TCP/443 -> 127.0.0.1:%d%s, table inet %s",
		opt->port, g_tpd.ipv6 ? " / [::1]" : "", TP_NFT_TABLE);
	if (g_tpd.dns_intercept)
		tpd_log("transparent mode: DNS (UDP+TCP/53) -> 127.0.0.1:%d%s, "
			"answered via %s", opt->dns_port, g_tpd.ipv6 ? " / [::1]" : "",
			g_tpd.doh != NULL ? "DNS-over-HTTPS" : "plain DNS");
	write_status("running");
	main_loop(lfd4, lfd6, nlfd);
	/* stop intercepting before anything else, so new connections go
	 * direct while we finish up */
	tp_nft_remove();
	save_decisions();
	write_status("stopped");
	tpd_log("stopped; nftables table %s removed", TP_NFT_TABLE);
	return (0);
}
