#include "tpd.h"
#include "compat.h"
#include "netfingerprint.h"
#include "tp_platform.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char	**environ;

/* ============================================================
 * macOS: PF (tp.h, tp_pf_ruleset for the rules themselves).
 *
 * - Interception: our rules live in the anchor TP_PF_ANCHOR, a child
 *   of the com.apple wildcard anchors that macOS's own /etc/pf.conf
 *   evaluates. /etc/pf.conf and the main ruleset are never modified;
 *   PF is enabled with a reference token (`pfctl -E`), which we
 *   release on stop (`pfctl -X`) — if nobody else holds one, PF goes
 *   back to disabled, exactly as before.
 * - Original destination: PF's state table, DIOCNATLOOK on /dev/pf.
 * - Own traffic: every socket we open binds a local port in
 *   TP_PF_OWN_PORT_LO..HI, which the rules skip (our SO_MARK).
 * - Fail-open: PF rules outlive a process, so a watchdog process
 *   (this binary, `--pf-watchdog`, spawned at install, in its own
 *   session) holds the read end of a pipe from the daemon. The daemon
 *   exits or dies -> end of file -> the watchdog removes our anchor
 *   and releases the PF token at once. The daemon hangs -> no
 *   heartbeat for TP_ALIVE_TIMEOUT_S -> the watchdog removes the
 *   anchor (the daemon reinstalls it if it recovers). Only if both
 *   are killed at the same instant do the rules stay, until launchd
 *   restarts the daemon (KeepAlive), which first removes stale rules.
 * - Network changes: a PF_ROUTE socket.
 * ============================================================ */

#define PFCTL "/sbin/pfctl"
#define PF_DEV "/dev/pf"
#define TOKEN_FILE_DEFAULT "/var/run/dpi-proxy/pf.token"
#define PFCTL_OUT_MAX 16384
#define RULES_MAX 8192

/* ---- DIOCNATLOOK (XNU bsd/net/pfvar.h; not in the public SDK) ---- */

struct s_pf_addr
{
	union
	{
		struct in_addr	v4;
		struct in6_addr	v6;
		uint8_t			addr8[16];
		uint32_t		addr32[4];
	}	pfa;
};

union u_pf_xport
{
	uint16_t	port;
	uint16_t	call_id;
	uint32_t	spi;
};

struct s_pfioc_natlook
{
	struct s_pf_addr	saddr;
	struct s_pf_addr	daddr;
	struct s_pf_addr	rsaddr;
	struct s_pf_addr	rdaddr;
	union u_pf_xport	sxport;
	union u_pf_xport	dxport;
	union u_pf_xport	rsxport;
	union u_pf_xport	rdxport;
	sa_family_t			af;
	uint8_t				proto;
	uint8_t				proto_variant;
	uint8_t				direction;
};

_Static_assert(sizeof(struct s_pfioc_natlook) == 84,
	"pfioc_natlook must match XNU's layout");

#define PF_DIR_OUT 2
#define DIOCNATLOOK _IOWR('D', 23, struct s_pfioc_natlook)

/* ---- state (install/refresh/remove: main thread only) ---- */

static int				g_pf = -1;
static int				g_route = -1;
static int				g_port;
static int				g_ipv6;
static int				g_dns_port;
static char				g_token[32];
static int				g_stale_done;
static pid_t			g_wd_pid = -1;
static int				g_wd_fd = -1;
static unsigned int		g_own_next;
/* last observed, for the status file */
static int				g_seen_enabled;
static int				g_seen_anchor;
static int				g_seen_hooks;
static int				g_removed;

static const char	*token_file(void)
{
	const char	*v;

	v = getenv("DPI_PROXY_PF_TOKEN_FILE");
	return ((v != NULL && v[0] != '\0') ? v : TOKEN_FILE_DEFAULT);
}

/* ---- running pfctl ---- */

/* Runs pfctl with `args` (NULL-terminated; fixed argv, no shell),
 * feeding `in` on stdin and collecting stdout+stderr into `out` (may be
 * NULL). The child inherits nothing but those three descriptors
 * (POSIX_SPAWN_CLOEXEC_DEFAULT) and default signal handling. Returns
 * pfctl's exit status, or -1. */
static int	pfctl_run(const char *const *args, const char *in, size_t in_len,
	char *out, size_t out_size)
{
	char						*argv[16];
	int							inp[2];
	int							outp[2];
	posix_spawn_file_actions_t	fa;
	posix_spawnattr_t			at;
	sigset_t					all;
	sigset_t					none;
	pid_t						pid;
	size_t						n;
	size_t						got;
	ssize_t						r;
	int							status;
	char						sink[1024];

	argv[0] = (char *)"pfctl";
	n = 0;
	while (args[n] != NULL && n < 14)
	{
		argv[n + 1] = (char *)args[n];
		n++;
	}
	argv[n + 1] = NULL;
	if (out != NULL && out_size > 0)
		out[0] = '\0';
	if (pipe(inp) != 0)
		return (-1);
	if (pipe(outp) != 0)
	{
		close(inp[0]);
		close(inp[1]);
		return (-1);
	}
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_adddup2(&fa, inp[0], STDIN_FILENO);
	posix_spawn_file_actions_adddup2(&fa, outp[1], STDOUT_FILENO);
	posix_spawn_file_actions_adddup2(&fa, outp[1], STDERR_FILENO);
	posix_spawnattr_init(&at);
	sigfillset(&all);
	sigemptyset(&none);
	posix_spawnattr_setsigdefault(&at, &all);
	posix_spawnattr_setsigmask(&at, &none);
	posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT
		| POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
	status = posix_spawn(&pid, PFCTL, &fa, &at, argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	posix_spawnattr_destroy(&at);
	close(inp[0]);
	close(outp[1]);
	if (status != 0)
	{
		close(inp[1]);
		close(outp[0]);
		return (-1);
	}
	got = 0;
	while (in != NULL && got < in_len)
	{
		r = write(inp[1], in + got, in_len - got);
		if (r < 0 && errno == EINTR)
			continue ;
		if (r <= 0)
			break ;
		got += (size_t)r;
	}
	close(inp[1]);
	got = 0;
	while (1)
	{
		if (out != NULL && got + 1 < out_size)
			r = read(outp[0], out + got, out_size - got - 1);
		else
			r = read(outp[0], sink, sizeof(sink));
		if (r < 0 && errno == EINTR)
			continue ;
		if (r <= 0)
			break ;
		if (out != NULL && got + 1 < out_size)
		{
			got += (size_t)r;
			out[got] = '\0';
		}
	}
	close(outp[0]);
	while (waitpid(pid, &status, 0) < 0)
	{
		if (errno != EINTR)
			return (-1);
	}
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static int	pfctl_simple(const char *a1, const char *a2, const char *a3,
	const char *a4)
{
	const char	*args[5];

	args[0] = a1;
	args[1] = a2;
	args[2] = a3;
	args[3] = a4;
	args[4] = NULL;
	return (pfctl_run(args, NULL, 0, NULL, 0));
}

static int	pfctl_show(const char *anchor, const char *what, char *out,
	size_t out_size)
{
	const char	*args[5];

	if (anchor != NULL)
	{
		args[0] = "-a";
		args[1] = anchor;
		args[2] = "-s";
		args[3] = what;
		args[4] = NULL;
	}
	else
	{
		args[0] = "-s";
		args[1] = what;
		args[2] = NULL;
	}
	return (pfctl_run(args, NULL, 0, out, out_size));
}

/* A line of `text` starts with `prefix`. */
static int	has_line(const char *text, const char *prefix)
{
	const char	*p;
	size_t		n;

	n = strlen(prefix);
	p = text;
	while (p != NULL && *p != '\0')
	{
		if (strncmp(p, prefix, n) == 0)
			return (1);
		p = strchr(p, '\n');
		if (p != NULL)
			p++;
	}
	return (0);
}

/* Lines that are rules (not pfctl's "No ALTQ support" noise). */
static size_t	rule_lines(const char *text)
{
	const char	*p;
	size_t		count;

	count = 0;
	p = text;
	while (p != NULL && *p != '\0')
	{
		if (*p != '\n' && strncmp(p, "No ALTQ", 7) != 0
			&& strncmp(p, "ALTQ", 4) != 0 && strncmp(p, "pfctl:", 6) != 0)
			count++;
		p = strchr(p, '\n');
		if (p != NULL)
			p++;
	}
	return (count);
}

/* ---- our anchor ---- */

/* Removes everything in our anchor — and only there: translation
 * rules, filter rules, tables. States of other connections, other
 * anchors and the main ruleset are untouched. */
static void	anchor_flush(void)
{
	pfctl_simple("-a", TP_PF_ANCHOR, "-F", "nat");
	pfctl_simple("-a", TP_PF_ANCHOR, "-F", "rules");
	pfctl_simple("-a", TP_PF_ANCHOR, "-F", "Tables");
}

static int	anchor_load(void)
{
	char		rules[RULES_MAX];
	char		out[PFCTL_OUT_MAX];
	const char	*args[5];
	size_t		len;
	int			rc;

	len = tp_pf_ruleset(rules, sizeof(rules), g_port, g_ipv6, g_dns_port);
	if (len == 0)
		return (-1);
	args[0] = "-a";
	args[1] = TP_PF_ANCHOR;
	args[2] = "-f";
	args[3] = "-";
	args[4] = NULL;
	rc = pfctl_run(args, rules, len, out, sizeof(out));
	if (rc != 0)
	{
		tpd_log("[PF] loading anchor %s failed (pfctl exit %d): %s",
			TP_PF_ANCHOR, rc, out);
		return (-1);
	}
	return (0);
}

static int	anchor_present(void)
{
	char	out[PFCTL_OUT_MAX];

	if (pfctl_show(TP_PF_ANCHOR, "nat", out, sizeof(out)) != 0
		|| strstr(out, "rdr pass on lo0") == NULL)
		return (0);
	if (pfctl_show(TP_PF_ANCHOR, "rules", out, sizeof(out)) != 0
		|| strstr(out, "route-to") == NULL)
		return (0);
	return (1);
}

/* Does the main ruleset evaluate the com.apple wildcard anchors (and so ours)? */
static int	main_hooks_present(int *main_empty)
{
	char	nat[PFCTL_OUT_MAX];
	char	rules[PFCTL_OUT_MAX];
	int		ok;

	*main_empty = 0;
	if (pfctl_show(NULL, "nat", nat, sizeof(nat)) != 0
		|| pfctl_show(NULL, "rules", rules, sizeof(rules)) != 0)
		return (0);
	ok = has_line(nat, "rdr-anchor \"com.apple/*\"")
		&& has_line(rules, "anchor \"com.apple/*\"");
	*main_empty = (rule_lines(nat) == 0 && rule_lines(rules) == 0);
	return (ok);
}

/* The hooks are normally there: launchd loads /etc/pf.conf at boot.
 * Only an entirely empty main ruleset is (re)loaded from the system's
 * own /etc/pf.conf, and only if that file has the hooks; a custom main
 * ruleset is never replaced. */
static int	ensure_main_hooks(void)
{
	int		empty;
	char	conf[8192];
	FILE	*f;
	size_t	n;

	if (main_hooks_present(&empty))
		return (0);
	if (empty)
	{
		f = fopen("/etc/pf.conf", "r");
		n = 0;
		if (f != NULL)
		{
			n = fread(conf, 1, sizeof(conf) - 1, f);
			fclose(f);
		}
		conf[n] = '\0';
		if (strstr(conf, "rdr-anchor \"com.apple/*\"") != NULL
			&& strstr(conf, "\nanchor \"com.apple/*\"") != NULL
			&& pfctl_simple("-f", "/etc/pf.conf", NULL, NULL) == 0
			&& main_hooks_present(&empty))
		{
			tpd_log("[PF] the main ruleset was empty; loaded the system "
				"default /etc/pf.conf (unchanged)");
			return (0);
		}
	}
	tpd_log("[PF] the loaded PF main ruleset does not evaluate the "
		"\"com.apple/*\" anchors (custom /etc/pf.conf?). Add these lines to "
		"it and reload it (sudo pfctl -f /etc/pf.conf):  rdr-anchor "
		"\"com.apple/*\"  and  anchor \"com.apple/*\"");
	return (-1);
}

/* ---- enable reference ---- */

static int	pf_enabled(void)
{
	char	out[PFCTL_OUT_MAX];

	if (pfctl_show(NULL, "info", out, sizeof(out)) != 0)
		return (0);
	return (strstr(out, "Status: Enabled") != NULL);
}

static void	token_file_write(void)
{
	char	tmp[PATH_MAX];
	FILE	*f;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", token_file()) >= (int)sizeof(tmp))
		return ;
	f = fopen(tmp, "w");
	if (f == NULL)
		return ;
	fprintf(f, "%s\n", g_token);
	if (fclose(f) != 0 || rename(tmp, token_file()) != 0)
		unlink(tmp);
}

static void	token_read(char *out, size_t out_size)
{
	FILE	*f;
	size_t	i;

	out[0] = '\0';
	f = fopen(token_file(), "r");
	if (f == NULL)
		return ;
	if (fgets(out, (int)out_size, f) == NULL)
		out[0] = '\0';
	fclose(f);
	i = 0;
	while (out[i] >= '0' && out[i] <= '9')
		i++;
	out[i] = '\0';
}

/* Deletes the token file only if it still holds `token` (a newer
 * daemon may have written its own). */
static void	token_file_forget(const char *token)
{
	char	cur[32];

	token_read(cur, sizeof(cur));
	if (cur[0] != '\0' && strcmp(cur, token) == 0)
		unlink(token_file());
}

static void	pf_release(const char *token)
{
	if (token[0] != '\0')
		pfctl_simple("-X", token, NULL, NULL);
}

static int	pf_enable(void)
{
	char		out[PFCTL_OUT_MAX];
	const char	*args[2];
	const char	*p;
	size_t		i;

	args[0] = "-E";
	args[1] = NULL;
	pfctl_run(args, NULL, 0, out, sizeof(out));
	p = strstr(out, "Token : ");
	if (p == NULL)
	{
		tpd_log("[PF] could not enable the packet filter: %s", out);
		return (-1);
	}
	p += 8;
	i = 0;
	while (p[i] >= '0' && p[i] <= '9' && i < sizeof(g_token) - 1)
	{
		g_token[i] = p[i];
		i++;
	}
	g_token[i] = '\0';
	if (i == 0)
		return (-1);
	token_file_write();
	return (0);
}

/* ---- watchdog (daemon side) ---- */

static void	wd_send(const char *msg)
{
	size_t	len;
	ssize_t	w;

	if (g_wd_fd < 0)
		return ;
	len = strlen(msg);
	do
		w = write(g_wd_fd, msg, len);
	while (w < 0 && errno == EINTR);
	if (w != (ssize_t)len)
	{
		close(g_wd_fd);
		g_wd_fd = -1;
	}
}

static void	wd_reap(int wait_ms)
{
	int		status;
	pid_t	r;

	while (g_wd_pid > 0)
	{
		r = waitpid(g_wd_pid, &status, WNOHANG);
		if (r == g_wd_pid || (r < 0 && errno != EINTR))
		{
			g_wd_pid = -1;
			return ;
		}
		if (wait_ms <= 0)
			return ;
		compat_sleep_ms(20);
		wait_ms -= 20;
	}
}

static int	self_path(char *out, size_t out_size)
{
	char		raw[PATH_MAX];
	uint32_t	size;

	size = sizeof(raw);
	if (_NSGetExecutablePath(raw, &size) != 0)
		return (-1);
	if (realpath(raw, out) == NULL)
		snprintf(out, out_size, "%s", raw);
	return (0);
}

static void	wd_send_token(void)
{
	char	msg[48];

	if (g_token[0] == '\0')
		return ;
	snprintf(msg, sizeof(msg), "t%s\n", g_token);
	wd_send(msg);
}

static int	wd_spawn(void)
{
	char						path[PATH_MAX];
	char						*argv[4];
	int							p[2];
	posix_spawn_file_actions_t	fa;
	posix_spawnattr_t			at;
	sigset_t					all;
	sigset_t					none;
	int							rc;
	const char					*log;

	if (self_path(path, sizeof(path)) != 0 || pipe(p) != 0)
		return (-1);
	log = g_tpd.opt.log_file;
	argv[0] = path;
	argv[1] = (char *)"--pf-watchdog";
	argv[2] = (char *)(log != NULL ? log : "");
	argv[3] = NULL;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_adddup2(&fa, p[0], STDIN_FILENO);
	posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null",
		O_WRONLY, 0);
	posix_spawn_file_actions_addinherit_np(&fa, STDERR_FILENO);
	posix_spawnattr_init(&at);
	sigfillset(&all);
	sigemptyset(&none);
	posix_spawnattr_setsigdefault(&at, &all);
	posix_spawnattr_setsigmask(&at, &none);
	posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT
		| POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
	rc = posix_spawn(&g_wd_pid, path, &fa, &at, argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	posix_spawnattr_destroy(&at);
	close(p[0]);
	if (rc != 0)
	{
		close(p[1]);
		g_wd_pid = -1;
		return (-1);
	}
	g_wd_fd = p[1];
	wd_send_token();
	return (0);
}

/* Heartbeat; restarts the watchdog if it is gone. */
static void	wd_beat(void)
{
	wd_reap(0);
	if (g_wd_pid > 0)
		wd_send("b");
	if (g_wd_pid <= 0 || g_wd_fd < 0)
	{
		if (g_wd_fd >= 0)
			close(g_wd_fd);
		g_wd_fd = -1;
		if (g_wd_pid > 0)
		{
			kill(g_wd_pid, SIGKILL);
			wd_reap(1000);
		}
		if (wd_spawn() == 0)
			tpd_log("[PF] watchdog (re)started, pid %d", (int)g_wd_pid);
		else
			tpd_log("[PF] cannot start the watchdog: %s", strerror(errno));
	}
}

static void	wd_stop(void)
{
	wd_send("q");
	if (g_wd_fd >= 0)
		close(g_wd_fd);
	g_wd_fd = -1;
	wd_reap(2000);
	if (g_wd_pid > 0)
	{
		kill(g_wd_pid, SIGKILL);
		wd_reap(1000);
	}
}

/* ---- tp_platform.h ---- */

int	tpp_init(void)
{
	struct rlimit	rl;

	g_pf = open(PF_DEV, O_RDONLY | O_CLOEXEC);
	if (g_pf < 0)
	{
		tpd_log("[PF] cannot open %s: %s (run as root)", PF_DEV,
			strerror(errno));
		return (-1);
	}
	if (access(PFCTL, X_OK) != 0)
	{
		tpd_log("[PF] %s not found", PFCTL);
		return (-1);
	}
	/* launchd's default of 256 descriptors is two browsers' worth */
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < 8192)
	{
		rl.rlim_cur = (rl.rlim_max < 8192) ? rl.rlim_max : 8192;
		setrlimit(RLIMIT_NOFILE, &rl);
	}
	g_own_next = (unsigned int)(getpid() * 2654435761u ^ (unsigned int)time(NULL));
	g_route = socket(PF_ROUTE, SOCK_RAW, 0);
	if (g_route >= 0)
	{
		fcntl(g_route, F_SETFD, FD_CLOEXEC);
		compat_set_nonblocking(g_route, 1);
	}
	return (0);
}

/* Left behind by a daemon that died together with its watchdog. */
static void	stale_cleanup(void)
{
	char	old[32];

	anchor_flush();
	token_read(old, sizeof(old));
	if (old[0] != '\0')
	{
		pf_release(old);
		token_file_forget(old);
		tpd_log("[PF] released a stale PF reference left by a previous run");
	}
}

int	tpp_install(int port, int ipv6, int dns_port)
{
	g_port = port;
	g_ipv6 = ipv6;
	g_dns_port = dns_port;
	g_removed = 0;
	if (!g_stale_done)
	{
		stale_cleanup();
		g_stale_done = 1;
	}
	g_seen_hooks = (ensure_main_hooks() == 0);
	if (!g_seen_hooks)
		return (-1);
	anchor_flush();
	if (anchor_load() != 0)
		return (-1);
	if (g_token[0] == '\0' || !pf_enabled())
	{
		if (g_token[0] != '\0')
		{
			tpd_log("[PF] the packet filter was disabled by someone else; "
				"enabling it again");
			pf_release(g_token);
			g_token[0] = '\0';
		}
		if (pf_enable() != 0)
		{
			anchor_flush();
			return (-1);
		}
		wd_send_token();
	}
	g_seen_enabled = 1;
	g_seen_anchor = anchor_present();
	wd_beat();
	return (g_seen_anchor ? 0 : -1);
}

int	tpp_refresh(void)
{
	int	hooks_empty;

	wd_beat();
	g_seen_enabled = pf_enabled();
	g_seen_anchor = anchor_present();
	g_seen_hooks = main_hooks_present(&hooks_empty);
	if (g_seen_enabled && g_seen_anchor && g_seen_hooks)
		return (0);
	if (tpp_install(g_port, g_ipv6, g_dns_port) == 0)
		return (1);
	return (-1);
}

void	tpp_remove(void)
{
	anchor_flush();
	if (g_token[0] != '\0')
	{
		pf_release(g_token);
		token_file_forget(g_token);
		g_token[0] = '\0';
	}
	wd_stop();
	g_seen_enabled = pf_enabled();
	g_seen_anchor = 0;
	g_removed = 1;
}

/* One pfctl run per family. */
void	tpp_quic_block(const t_dns_addr *addrs, size_t n)
{
	char		text[DNS_MAX_ADDRS][INET6_ADDRSTRLEN];
	const char	*args[6 + DNS_MAX_ADDRS];
	size_t		i;
	size_t		k;
	int			fam;

	fam = 4;
	while (fam <= 6)
	{
		args[0] = "-a";
		args[1] = TP_PF_ANCHOR;
		args[2] = "-t";
		args[3] = fam == 4 ? TP_PF_QUIC_TABLE4 : TP_PF_QUIC_TABLE6;
		args[4] = "-T";
		args[5] = "add";
		k = 6;
		i = 0;
		while (i < n && i < DNS_MAX_ADDRS && k < 14)
		{
			if (addrs[i].family == fam && inet_ntop(fam == 6 ? AF_INET6
					: AF_INET, addrs[i].addr, text[i], sizeof(text[i])) != NULL)
				args[k++] = text[i];
			i++;
		}
		args[k] = NULL;
		if (k > 6)
			pfctl_run(args, NULL, 0, NULL, 0);
		fam += 2;
	}
}

void	tpp_quic_flush(void)
{
	const char	*args[7];

	args[0] = "-a";
	args[1] = TP_PF_ANCHOR;
	args[2] = "-t";
	args[3] = TP_PF_QUIC_TABLE4;
	args[4] = "-T";
	args[5] = "flush";
	args[6] = NULL;
	pfctl_run(args, NULL, 0, NULL, 0);
	args[3] = TP_PF_QUIC_TABLE6;
	pfctl_run(args, NULL, 0, NULL, 0);
}

int	tpp_listen_wildcard(void)
{
	return (0);
}

/* (peer -> local) is the translated connection as our socket sees it;
 * PF's state for it knows where the peer was really going. */
static int	natlook(int proto, const struct sockaddr_storage *peer,
	const struct sockaddr_storage *local, struct sockaddr_storage *out,
	socklen_t *out_len)
{
	struct s_pfioc_natlook	nl;
	struct sockaddr_in		*o4;
	struct sockaddr_in6		*o6;

	if (g_pf < 0 || peer->ss_family != local->ss_family)
		return (-1);
	memset(&nl, 0, sizeof(nl));
	nl.af = peer->ss_family;
	nl.proto = (uint8_t)proto;
	nl.direction = PF_DIR_OUT;
	if (peer->ss_family == AF_INET)
	{
		nl.saddr.pfa.v4 = ((const struct sockaddr_in *)peer)->sin_addr;
		nl.sxport.port = ((const struct sockaddr_in *)peer)->sin_port;
		nl.daddr.pfa.v4 = ((const struct sockaddr_in *)local)->sin_addr;
		nl.dxport.port = ((const struct sockaddr_in *)local)->sin_port;
	}
	else if (peer->ss_family == AF_INET6)
	{
		nl.saddr.pfa.v6 = ((const struct sockaddr_in6 *)peer)->sin6_addr;
		nl.sxport.port = ((const struct sockaddr_in6 *)peer)->sin6_port;
		nl.daddr.pfa.v6 = ((const struct sockaddr_in6 *)local)->sin6_addr;
		nl.dxport.port = ((const struct sockaddr_in6 *)local)->sin6_port;
	}
	else
		return (-1);
	if (ioctl(g_pf, DIOCNATLOOK, &nl) != 0)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (nl.af == AF_INET)
	{
		o4 = (struct sockaddr_in *)out;
		o4->sin_len = sizeof(*o4);
		o4->sin_family = AF_INET;
		o4->sin_addr = nl.rdaddr.pfa.v4;
		o4->sin_port = nl.rdxport.port;
		*out_len = sizeof(*o4);
		/* translated to itself: not something we redirected */
		if ((ntohl(o4->sin_addr.s_addr) >> 24) == 127
			|| o4->sin_addr.s_addr == INADDR_ANY)
			return (-1);
	}
	else
	{
		o6 = (struct sockaddr_in6 *)out;
		o6->sin6_len = sizeof(*o6);
		o6->sin6_family = AF_INET6;
		o6->sin6_addr = nl.rdaddr.pfa.v6;
		o6->sin6_port = nl.rdxport.port;
		*out_len = sizeof(*o6);
		if (IN6_IS_ADDR_LOOPBACK(&o6->sin6_addr)
			|| IN6_IS_ADDR_UNSPECIFIED(&o6->sin6_addr)
			|| IN6_IS_ADDR_V4MAPPED(&o6->sin6_addr))
			return (-1);
	}
	return (0);
}

static int	socket_ends(int fd, const struct sockaddr *peer, socklen_t peer_len,
	struct sockaddr_storage *p, struct sockaddr_storage *l)
{
	socklen_t	len;

	memset(p, 0, sizeof(*p));
	if (peer != NULL)
	{
		if (peer_len > sizeof(*p))
			return (-1);
		memcpy(p, peer, peer_len);
	}
	else
	{
		len = sizeof(*p);
		if (getpeername(fd, (struct sockaddr *)p, &len) != 0)
			return (-1);
	}
	len = sizeof(*l);
	if (getsockname(fd, (struct sockaddr *)l, &len) != 0)
		return (-1);
	return (0);
}

int	tpp_original_dst(int client_fd, int family, struct sockaddr_storage *out,
	socklen_t *out_len)
{
	struct sockaddr_storage	peer;
	struct sockaddr_storage	local;

	(void)family;
	if (socket_ends(client_fd, NULL, 0, &peer, &local) != 0)
		return (-1);
	return (natlook(IPPROTO_TCP, &peer, &local, out, out_len));
}

int	tpp_dns_peer_ok(const struct sockaddr *peer, socklen_t len, int tcp)
{
	/* the forwarder only listens on loopback */
	(void)peer;
	(void)len;
	(void)tcp;
	return (1);
}

int	tpp_dns_original(int fd, const struct sockaddr *peer, socklen_t peer_len,
	int tcp, struct sockaddr_storage *out, socklen_t *out_len)
{
	struct sockaddr_storage	p;
	struct sockaddr_storage	l;

	if (socket_ends(fd, peer, peer_len, &p, &l) != 0)
		return (-1);
	return (natlook(tcp ? IPPROTO_TCP : IPPROTO_UDP, &p, &l, out, out_len));
}

/* Our sockets come from TP_PF_OWN_PORT_LO..HI, which the rules skip. */
int	tpp_prepare_socket(int fd, int family)
{
	struct sockaddr_storage	ss;
	unsigned int			span;
	int						tries;
	int						port;
	socklen_t				len;

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	compat_setsockopt_int(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
	/* a port whose last connection is in TIME_WAIT can be bound again;
	 * connecting the very same 4-tuple fails, and tpd_connect retries */
	compat_setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
	span = TP_PF_OWN_PORT_HI - TP_PF_OWN_PORT_LO + 1;
	tries = 0;
	while (tries++ < 64)
	{
		port = TP_PF_OWN_PORT_LO
			+ (int)(__atomic_fetch_add(&g_own_next, 1, __ATOMIC_RELAXED) % span);
		memset(&ss, 0, sizeof(ss));
		if (family == AF_INET6)
		{
			((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
			((struct sockaddr_in6 *)&ss)->sin6_port = htons((uint16_t)port);
			len = sizeof(struct sockaddr_in6);
		}
		else
		{
			((struct sockaddr_in *)&ss)->sin_family = AF_INET;
			((struct sockaddr_in *)&ss)->sin_port = htons((uint16_t)port);
			len = sizeof(struct sockaddr_in);
		}
		ss.ss_len = (uint8_t)len;
		if (bind(fd, (struct sockaddr *)&ss, len) == 0)
			return (0);
		if (errno != EADDRINUSE && errno != EACCES)
			return (-1);
	}
	return (-1);
}

/* ---- network changes and fingerprint ---- */

int	tpp_netwatch_fd(void)
{
	return (g_route);
}

/* Only address, link and non-host route changes matter; macOS also
 * reports every cloned per-destination and ARP route, which would
 * otherwise keep postponing the settle timer during normal traffic. */
int	tpp_netwatch_drain(void)
{
	char				buf[4096];
	ssize_t				n;
	struct rt_msghdr	*rtm;
	int					relevant;

	relevant = 0;
	if (g_route < 0)
		return (0);
	while ((n = recv(g_route, buf, sizeof(buf), 0)) > 0)
	{
		if ((size_t)n < sizeof(struct rt_msghdr))
			continue ;
		rtm = (struct rt_msghdr *)(void *)buf;
		if (rtm->rtm_type == RTM_NEWADDR || rtm->rtm_type == RTM_DELADDR
			|| rtm->rtm_type == RTM_IFINFO)
			relevant = 1;
		else if ((rtm->rtm_type == RTM_ADD || rtm->rtm_type == RTM_DELETE
				|| rtm->rtm_type == RTM_CHANGE)
			&& !(rtm->rtm_flags & (RTF_HOST | RTF_WASCLONED | RTF_LLINFO)))
			relevant = 1;
	}
	return (relevant);
}

#define SA_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) \
	: sizeof(uint32_t))

/* The sockaddrs after a routing message header, by RTA_* index. */
static void	rt_addrs(struct rt_msghdr *rtm, const char *end,
	struct sockaddr **sa)
{
	char	*p;
	int		i;

	p = (char *)(rtm + 1);
	i = 0;
	while (i < RTAX_MAX)
	{
		sa[i] = NULL;
		if ((rtm->rtm_addrs & (1 << i)) && p < end)
		{
			sa[i] = (struct sockaddr *)(void *)p;
			p += SA_ROUNDUP(sa[i]->sa_len);
		}
		i++;
	}
}

static char	*route_dump(int family, int flags, size_t *len)
{
	int		mib[6];
	char	*buf;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = family;
	mib[4] = NET_RT_FLAGS;
	mib[5] = flags;
	if (sysctl(mib, 6, NULL, len, NULL, 0) != 0 || *len == 0)
		return (NULL);
	*len += *len / 2;
	buf = malloc(*len);
	if (buf != NULL && sysctl(mib, 6, buf, len, NULL, 0) != 0)
	{
		free(buf);
		return (NULL);
	}
	return (buf);
}

static uint64_t	fnv(uint64_t h, const void *data, size_t len)
{
	const uint8_t	*p;
	size_t			i;

	p = data;
	i = 0;
	while (i < len)
		h = (h ^ p[i++]) * 1099511628211ULL;
	return (h);
}

/* The primary IPv4 default route (not an interface-scoped one): its
 * gateway and interface. */
static int	default_route_v4(struct in_addr *gw, unsigned short *ifindex)
{
	char				*buf;
	char				*p;
	size_t				len;
	struct rt_msghdr	*rtm;
	struct sockaddr		*sa[RTAX_MAX];
	int					found;

	buf = route_dump(AF_INET, RTF_GATEWAY, &len);
	if (buf == NULL)
		return (0);
	found = 0;
	p = buf;
	while (!found && p + sizeof(*rtm) <= buf + len)
	{
		rtm = (struct rt_msghdr *)(void *)p;
		if (rtm->rtm_msglen == 0)
			break ;
		rt_addrs(rtm, p + rtm->rtm_msglen, sa);
		if (sa[RTAX_DST] != NULL && sa[RTAX_DST]->sa_family == AF_INET
			&& ((struct sockaddr_in *)(void *)sa[RTAX_DST])->sin_addr.s_addr == 0
			&& sa[RTAX_GATEWAY] != NULL
			&& sa[RTAX_GATEWAY]->sa_family == AF_INET
			&& (rtm->rtm_flags & RTF_UP) && !(rtm->rtm_flags & RTF_IFSCOPE))
		{
			*gw = ((struct sockaddr_in *)(void *)sa[RTAX_GATEWAY])->sin_addr;
			*ifindex = rtm->rtm_index;
			found = 1;
		}
		p += rtm->rtm_msglen;
	}
	free(buf);
	return (found);
}

/* MAC address of `gw` from the ARP table (0 bytes if unknown). */
static size_t	gateway_mac(struct in_addr gw, uint8_t *mac, size_t mac_size)
{
	char				*buf;
	char				*p;
	size_t				len;
	size_t				n;
	struct rt_msghdr	*rtm;
	struct sockaddr		*sa[RTAX_MAX];
	struct sockaddr_dl	*sdl;

	buf = route_dump(AF_INET, RTF_LLINFO, &len);
	if (buf == NULL)
		return (0);
	n = 0;
	p = buf;
	while (n == 0 && p + sizeof(*rtm) <= buf + len)
	{
		rtm = (struct rt_msghdr *)(void *)p;
		if (rtm->rtm_msglen == 0)
			break ;
		rt_addrs(rtm, p + rtm->rtm_msglen, sa);
		if (sa[RTAX_DST] != NULL && sa[RTAX_DST]->sa_family == AF_INET
			&& ((struct sockaddr_in *)(void *)sa[RTAX_DST])->sin_addr.s_addr
			== gw.s_addr && sa[RTAX_GATEWAY] != NULL
			&& sa[RTAX_GATEWAY]->sa_family == AF_LINK)
		{
			sdl = (struct sockaddr_dl *)(void *)sa[RTAX_GATEWAY];
			n = sdl->sdl_alen < mac_size ? sdl->sdl_alen : mac_size;
			memcpy(mac, LLADDR(sdl), n);
		}
		p += rtm->rtm_msglen;
	}
	free(buf);
	return (n);
}

/* Default route's interface + gateway + the gateway's MAC (which tells
 * apart two networks that both use 192.168.1.1). IPv6-only networks:
 * the interface of the IPv6 default route. */
uint64_t	tpp_network_fingerprint(void)
{
	struct in_addr	gw;
	unsigned short	ifindex;
	char			name[IF_NAMESIZE];
	uint8_t			mac[16];
	size_t			maclen;
	uint64_t		h;

	h = 1469598103934665603ULL;
	if (!default_route_v4(&gw, &ifindex))
		return (NETFP_UNKNOWN);
	if (if_indextoname(ifindex, name) != NULL)
		h = fnv(h, name, strlen(name));
	h = fnv(h, &gw, sizeof(gw));
	maclen = gateway_mac(gw, mac, sizeof(mac));
	h = fnv(h, mac, maclen);
	return (h == NETFP_UNKNOWN ? 1 : h);
}

/* ---- the rest ---- */

/* Other macOS DPI tools that intercept or proxy the same traffic. */
const char	*tpp_conflict(void)
{
	static const struct
	{
		const char	*proc;
		const char	*text;
	}		known[] = {
		{"tpws", "zapret (tpws) is running"},
		{"spoofdpi", "SpoofDPI is running"},
		{"ciadpi", "ByeDPI (ciadpi) is running"},
		{"byedpi", "ByeDPI is running"},
		{"dpi-bypass", "dpi-bypass is running"},
		{NULL, NULL}
	};
	pid_t			pids[4096];
	int				n;
	int				i;
	size_t			k;
	char			name[2 * MAXCOMLEN + 1];

	n = proc_listallpids(pids, (int)sizeof(pids));
	i = 0;
	while (i < n && i < (int)(sizeof(pids) / sizeof(pids[0])))
	{
		if (pids[i] > 0 && proc_name(pids[i], name, sizeof(name)) > 0)
		{
			k = 0;
			while (known[k].proc != NULL)
			{
				if (strcmp(name, known[k].proc) == 0)
					return (known[k].text);
				k++;
			}
		}
		i++;
	}
	return (NULL);
}

const char	*tpp_name(void)
{
	return ("PF");
}

void	tpp_status_extra(char *out, size_t out_size)
{
	char	wd[64];

	if (g_wd_pid > 0)
		snprintf(wd, sizeof(wd), "running (pid %d)", (int)g_wd_pid);
	else
		snprintf(wd, sizeof(wd), "not running");
	snprintf(out, out_size, "pf: %s\npf_anchor: %s %s\npf_hooks: %s\n"
		"pf_watchdog: %s\n",
		g_seen_enabled ? "enabled" : "disabled", TP_PF_ANCHOR,
		g_removed ? "removed" : (g_seen_anchor ? "loaded" : "MISSING"),
		g_seen_hooks ? "ok" : "MISSING", wd);
}

/* ---- the watchdog process: `dpi-proxy --pf-watchdog LOGFILE` ---- */

static volatile sig_atomic_t	g_wd_term;
static const char				*g_wd_log;

static void	wd_on_signal(int sig)
{
	(void)sig;
	g_wd_term = 1;
}

static void	wd_log(const char *msg)
{
	FILE		*f;
	char		stamp[32];
	time_t		now;
	struct tm	tm;

	now = time(NULL);
	localtime_r(&now, &tm);
	strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm);
	fprintf(stderr, "[watchdog] %s\n", msg);
	if (g_wd_log == NULL || g_wd_log[0] == '\0')
		return ;
	f = fopen(g_wd_log, "a");
	if (f == NULL)
		return ;
	fprintf(f, "%s [watchdog] %s\n", stamp, msg);
	fclose(f);
}

/* Fail-open cleanup: our anchor gone, our PF reference released. */
static void	wd_cleanup(const char *token)
{
	anchor_flush();
	if (token[0] != '\0')
	{
		pf_release(token);
		token_file_forget(token);
	}
}

int	tp_pf_watchdog_main(const char *log_file)
{
	struct sigaction	sa;
	struct pollfd		pfd;
	char				buf[256];
	char				token[32];
	size_t				tlen;
	int					in_token;
	int					clean;
	int					flushed;
	int64_t				last;
	ssize_t				n;
	ssize_t				i;

	g_wd_log = log_file;
	setsid();
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = wd_on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	token[0] = '\0';
	tlen = 0;
	in_token = 0;
	clean = 0;
	flushed = 0;
	last = compat_now_ms();
	while (1)
	{
		pfd.fd = STDIN_FILENO;
		pfd.events = POLLIN;
		pfd.revents = 0;
		n = 0;
		if (poll(&pfd, 1, 1000) > 0)
		{
			n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n < 0 && errno == EINTR)
				n = 0;
			else if (n <= 0)
				break ;
			i = 0;
			while (i < n)
			{
				if (in_token && buf[i] >= '0' && buf[i] <= '9'
					&& tlen < sizeof(token) - 1)
					token[tlen++] = buf[i];
				else if (in_token)
				{
					token[tlen] = '\0';
					in_token = 0;
				}
				else if (buf[i] == 't')
				{
					in_token = 1;
					tlen = 0;
				}
				else if (buf[i] == 'q')
					clean = 1;
				else if (buf[i] == 'b')
				{
					last = compat_now_ms();
					flushed = 0;
				}
				i++;
			}
		}
		if (g_wd_term)
		{
			wd_cleanup(token);
			wd_log("stopped by a signal; dpi-proxy PF rules removed");
			return (0);
		}
		if (!flushed && compat_now_ms() - last > TP_ALIVE_TIMEOUT_S * 1000)
		{
			anchor_flush();
			flushed = 1;
			wd_log("no heartbeat from dpi-proxy for 30 s (hung?): PF rules "
				"removed, traffic goes out directly (fail-open)");
		}
	}
	if (!clean)
	{
		wd_cleanup(token);
		wd_log("dpi-proxy exited unexpectedly: PF rules removed and PF "
			"reference released, traffic goes out directly (fail-open)");
	}
	return (0);
}
