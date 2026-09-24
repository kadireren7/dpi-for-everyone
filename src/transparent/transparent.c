#define _GNU_SOURCE
#include "tpd.h"
#include "compat.h"
#include "netfingerprint.h"
#include "tp_platform.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ============================================================
 * `dpi-proxy --mode transparent`: the SOCKS proxy's stream core
 * (relay.c) behind a listener that the platform layer (tp_platform.h:
 * nftables on Linux, WinDivert on Windows) redirects outgoing TCP/443
 * to. See tp.h for the decision model and docs/transparent-mode.md for
 * operation.
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
	return (compat_now_ms());
}

/* Log lines go to stderr (the journal, under systemd) and, when a log
 * file is configured (the Windows service has no journal), appended
 * there with a timestamp; the file is rotated to <file>.1 at 4 MB. */
#define LOG_FILE_MAX (4L * 1024 * 1024)

static pthread_mutex_t	g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static void	log_to_file(const char *line)
{
	FILE		*f;
	char		old[4096];
	char		stamp[32];
	time_t		now;
	struct tm	tm;
	long		size;

	f = fopen(g_tpd.opt.log_file, "a");
	if (f == NULL)
		return ;
	now = time(NULL);
#ifdef _WIN32
	localtime_s(&tm, &now);
#else
	localtime_r(&now, &tm);
#endif
	strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm);
	fprintf(f, "%s %s\n", stamp, line);
	size = ftell(f);
	fclose(f);
	if (size > LOG_FILE_MAX && snprintf(old, sizeof(old), "%s.1",
			g_tpd.opt.log_file) < (int)sizeof(old))
	{
		remove(old);
		rename(g_tpd.opt.log_file, old);
	}
}

static void	vlog(const char *fmt, va_list ap)
{
	char	line[1024];

	vsnprintf(line, sizeof(line), fmt, ap);
	fprintf(stderr, "%s\n", line);
	if (g_tpd.opt.log_file != NULL)
	{
		pthread_mutex_lock(&g_log_lock);
		log_to_file(line);
		pthread_mutex_unlock(&g_log_lock);
	}
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

#ifdef _WIN32

/* %ProgramData%\dpi-proxy\<name> */
static const char	*data_path(const char *name)
{
	static char	paths[4][512];
	static int	next;
	const char	*base;
	char		*p;

	base = getenv("ProgramData");
	if (base == NULL || base[0] == '\0')
		base = "C:\\ProgramData";
	p = paths[next++ % 4];
	snprintf(p, sizeof(paths[0]), "%s\\dpi-proxy\\%s", base, name);
	return (p);
}
# define DEFAULT_STRATEGY_CONF data_path("strategy.conf")
# define DEFAULT_DECISIONS data_path("tp-decisions.conf")
# define DEFAULT_STATUS data_path("transparent.status")
# define DEFAULT_LOG_FILE data_path("dpi-proxy.log")
#else
# define DEFAULT_STRATEGY_CONF "/etc/dpi-proxy/strategy.conf"
# define DEFAULT_DECISIONS "/var/lib/dpi-proxy/tp-decisions.conf"
# define DEFAULT_STATUS "/run/dpi-proxy/transparent.status"
/* under systemd, stderr is the journal */
# define DEFAULT_LOG_FILE NULL
#endif

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
			DEFAULT_STRATEGY_CONF);
	opt->decisions_file = env_or("DPI_PROXY_TP_DECISIONS", DEFAULT_DECISIONS);
	opt->status_file = env_or("DPI_PROXY_TP_STATUS", DEFAULT_STATUS);
	opt->log_file = env_or("DPI_PROXY_LOG_FILE", DEFAULT_LOG_FILE);
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
	f = fopen(tmp, "wb");
	if (f == NULL)
		return (-1);
	w = fwrite(data, 1, len, f);
	if (fclose(f) != 0 || w != len || compat_rename_replace(tmp, path) != 0)
	{
		remove(tmp);
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
			"conflict: %s\ninterception: %s\n",
			engine, (int)getpid(), g_tpd.started_at, tpd_now(),
			g_tpd.opt.port, dns_ok ? "healthy" : "degraded", fp,
			s.flows_total, s.flows_active, s.passthrough, s.direct,
			s.bypassed, s.failed, s.verified_ok, s.verified_bad, ndec,
			learned[0] ? learned : "-",
			g_tpd.dns_intercept ? (g_tpd.doh ? "doh" : "plain") : "off",
			s.dns_queries, s.dns_failures,
			g_tpd.conflict && g_tpd.conflict_text ? g_tpd.conflict_text
			: "none", tpp_name());
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
	const char	*seen;

	seen = tpp_conflict();
	if (seen != NULL && !g_tpd.conflict)
		tpd_log("[conflict] WARNING: %s. Two transparent interceptors "
			"proxy each other's traffic and break connections: stop one "
			"(e.g. `sudo systemctl stop dpi-bypass`).", seen);
	else if (seen == NULL && g_tpd.conflict)
		tpd_log("[conflict] the other interceptor is gone; no conflict");
	g_tpd.conflict = (seen != NULL);
	g_tpd.conflict_text = seen;
}

/* ---- network watch ---- */

/* Recomputes the network fingerprint; on a change, forgets what was
 * specific to the old network (DNS answers, cooldowns, direct-bad
 * marks, QUIC blocks). Learned decisions are keyed by fingerprint,
 * so switching back later finds them again. */
static void	check_network(void)
{
	uint64_t	fp;
	uint64_t	old;

	fp = tpp_network_fingerprint();
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
	tpp_quic_flush();
	tpd_quic_forget();
	tpd_log("[network] profile %016" PRIx64 " -> %016" PRIx64 "%s", old, fp,
		fp == NETFP_UNKNOWN ? " (no default route: nothing is learned "
		"until one appears)" : "");
}

/* ---- listeners ---- */

int	tpd_listen(int family, int type, int port)
{
	int					fd;
	struct sockaddr_in	v4;
	struct sockaddr_in6	v6;
	int					rc;

	fd = (int)socket(family, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);
#ifdef _WIN32
	/* Windows' SO_REUSEADDR would let another process bind the same
	 * port; exclusive use is the equivalent of the POSIX behavior */
	compat_setsockopt_int(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
	compat_setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
#endif
	if (family == AF_INET6)
	{
		compat_setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
		memset(&v6, 0, sizeof(v6));
		v6.sin6_family = AF_INET6;
		v6.sin6_addr = tpp_listen_wildcard() ? in6addr_any : in6addr_loopback;
		v6.sin6_port = htons((uint16_t)port);
		rc = bind(fd, (struct sockaddr *)&v6, sizeof(v6));
	}
	else
	{
		memset(&v4, 0, sizeof(v4));
		v4.sin_family = AF_INET;
		v4.sin_addr.s_addr = htonl(tpp_listen_wildcard() ? INADDR_ANY
				: INADDR_LOOPBACK);
		v4.sin_port = htons((uint16_t)port);
		rc = bind(fd, (struct sockaddr *)&v4, sizeof(v4));
	}
	if (rc < 0 || (type == SOCK_STREAM && listen(fd, 512) < 0))
	{
		compat_close(fd);
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

int	tpd_accept(int listen_fd)
{
#ifdef __linux__
	/* close-on-exec: the nft helper runs in forked children */
	return (accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC));
#else
	return ((int)accept(listen_fd, NULL, NULL));
#endif
}

static void	accept_one(int listen_fd, int family, pthread_attr_t *attr)
{
	int			fd;
	t_conn_arg	*arg;
	pthread_t	tid;

	fd = tpd_accept(listen_fd);
	if (fd < 0)
		return ;
	arg = malloc(sizeof(*arg));
	if (arg == NULL)
	{
		compat_close(fd);
		return ;
	}
	arg->fd = fd;
	arg->family = family;
	if (pthread_create(&tid, attr, conn_thread, arg) != 0)
	{
		tpd_log("[conn] could not start a thread: %s", strerror(errno));
		compat_close(fd);
		free(arg);
	}
}

/* ---- main loop ---- */

void	tp_request_stop(void)
{
	g_stop = 1;
}

#ifdef _WIN32

static void	on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void	install_signals(void)
{
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
}

#else

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

#endif

static void	heartbeat(void)
{
	int	rc;

	rc = tpp_refresh();
	if (rc == 1)
		tpd_log("[%s] interception was missing or broken; reinstalled",
			tpp_name());
	else if (rc < 0)
		tpd_log("[%s] reinstall failed; traffic is NOT intercepted "
			"(fail-open)", tpp_name());
	save_decisions();
	write_status("running");
}

static void	main_loop(int lfd4, int lfd6)
{
	t_pollfd		pfd[3];
	pthread_attr_t	attr;
	int64_t			next_beat;
	int64_t			net_due;
	int64_t			next_netcheck;
	int64_t			now;
	int				nlfd;
	size_t			n;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, CONN_STACK_SIZE);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	next_beat = tpd_now_ms() + TP_HEARTBEAT_S * 1000;
	next_netcheck = tpd_now_ms() + NETCHECK_INTERVAL_S * 1000;
	net_due = 0;
	nlfd = tpp_netwatch_fd();
	while (!g_stop)
	{
		memset(pfd, 0, sizeof(pfd));
		n = 0;
		pfd[n].fd = lfd4;
		pfd[n++].events = POLLIN;
		if (lfd6 >= 0)
		{
			pfd[n].fd = lfd6;
			pfd[n++].events = POLLIN;
		}
		if (nlfd >= 0)
		{
			pfd[n].fd = nlfd;
			pfd[n++].events = POLLIN;
		}
		if (compat_poll(pfd, n, 1000) < 0 && !compat_interrupted())
			break ;
		if (pfd[0].revents & POLLIN)
			accept_one(lfd4, AF_INET, &attr);
		if (lfd6 >= 0 && (pfd[1].revents & POLLIN))
			accept_one(lfd6, AF_INET6, &attr);
		now = tpd_now_ms();
		if (nlfd >= 0 && (pfd[n - 1].revents & POLLIN))
		{
			tpp_netwatch_drain();
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
	int			lfd4;
	int			lfd6;
	const char	*where;

	memset(&g_tpd, 0, sizeof(g_tpd));
	g_tpd.opt = *opt;
	g_tpd.started_at = tpd_now();
	g_stop = 0;
	pthread_mutex_init(&g_tpd.lock, NULL);
	tp_decisions_init(&g_tpd.dec);
	install_signals();
	if (tpp_init() != 0)
	{
		tpd_log("cannot initialize the %s platform layer", tpp_name());
		return (-1);
	}
	dns_set_socket_hook(tpp_prepare_socket);
	if (init_dns() != 0)
		return (-1);
	load_strategy_conf();
	g_tpd.fp = tpp_network_fingerprint();
	load_decisions();
	tpd_log("[network] profile %016" PRIx64, g_tpd.fp);
	where = tpp_listen_wildcard() ? "*" : "127.0.0.1";
	/* listeners first: the redirect must never point at nothing */
	lfd4 = tpd_listen(AF_INET, SOCK_STREAM, opt->port);
	if (lfd4 < 0)
	{
		tpd_log("cannot listen on %s:%d: %s", where, opt->port,
			compat_sock_strerror());
		return (-1);
	}
	lfd6 = tpd_listen(AF_INET6, SOCK_STREAM, opt->port);
	if (lfd6 < 0)
		tpd_log("note: no IPv6 listener on port %d (%s); IPv6 is left alone",
			opt->port, compat_sock_strerror());
	g_tpd.ipv6 = (lfd6 >= 0);
	if (opt->dns_port > 0)
	{
		if (tpd_dnsfwd_start(opt->dns_port, &g_tpd.ipv6) == 0)
			g_tpd.dns_intercept = 1;
		else
			tpd_log("[dns] cannot listen on %s:%d (%s); DNS is NOT "
				"intercepted — blocked names may resolve to block pages",
				where, opt->dns_port, compat_sock_strerror());
	}
	check_conflicts();
	if (tpd_verify_start() != 0 || tpp_install(opt->port, g_tpd.ipv6,
			g_tpd.dns_intercept ? opt->dns_port : 0) != 0)
	{
		tpd_log("cannot install %s interception (needs administrator/root "
			"rights%s)", tpp_name(),
			strcmp(tpp_name(), "nftables") == 0
			? ", CAP_NET_ADMIN and the nft binary" : "");
		tpp_remove();
		compat_close(lfd4);
		if (lfd6 >= 0)
			compat_close(lfd6);
		return (-1);
	}
	tpd_log("transparent mode: TCP/443 -> %s:%d%s via %s", where, opt->port,
		g_tpd.ipv6 ? " (+IPv6)" : "", tpp_name());
	if (g_tpd.dns_intercept)
		tpd_log("transparent mode: DNS (UDP+TCP/53) -> %s:%d%s, "
			"answered via %s", where, opt->dns_port,
			g_tpd.ipv6 ? " (+IPv6)" : "",
			g_tpd.doh != NULL ? "DNS-over-HTTPS" : "plain DNS");
	write_status("running");
	main_loop(lfd4, lfd6);
	/* stop intercepting before anything else, so new connections go
	 * direct while we finish up */
	tpp_remove();
	save_decisions();
	write_status("stopped");
	tpd_log("stopped; %s interception removed", tpp_name());
	return (0);
}
