#ifndef TP_SYS_H
# define TP_SYS_H

# include <stddef.h>

/* ============================================================
 * Transparent mode entry point (src/transparent/transparent.c) and
 * its options. The pure decision logic lives in tp.h, the platform
 * interception layer in tp_platform.h.
 * ============================================================ */

typedef struct s_tp_options
{
	int			port;				/* loopback listener port */
	int			debug;				/* per-connection log lines */
	const char	*strategy_conf;		/* manual rules (strategy.conf) */
	const char	*decisions_file;	/* learned decisions */
	const char	*status_file;		/* for `dpi-proxy-ctl status` */
	const char	*log_file;			/* also log here (NULL: stderr only) */
	const char	*dns_servers;		/* plain-DNS fallback: IP literals */
	/* local DNS forwarder: 0 = don't intercept DNS at all */
	int			dns_port;
	/* resolve over DNS-over-HTTPS (1.1.1.1, 8.8.8.8, 9.9.9.9) first,
	 * plain UDP only when every DoH server failed; 0 = UDP only */
	int			doh;
}	t_tp_options;

/* Fills defaults, then applies DPI_PROXY_* environment overrides. */
void	tp_options_default(t_tp_options *opt);

/* Runs until SIGTERM/SIGINT or tp_request_stop(); removes the
 * interception on the way out. Returns 0 on a clean stop, -1 if
 * startup failed. */
int		run_transparent_server(const t_tp_options *opt);
/* Asks a running server to stop (e.g. from a Windows service
 * control handler); returns immediately. */
void	tp_request_stop(void);

# ifdef _WIN32
/* svc_windows.c: runs the server under the service control manager
 * (service "dpi-proxy"); -1 if not started by it. */
int		tp_windows_service_run(const t_tp_options *opt);
# endif

# ifdef __APPLE__
/* platform_macos.c: `dpi-proxy --pf-watchdog LOGFILE`, spawned by the
 * daemon itself: removes the PF rules the moment the daemon dies. */
int		tp_pf_watchdog_main(const char *log_file);
# endif

#endif
