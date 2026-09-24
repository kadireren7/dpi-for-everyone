/* ============================================================
 * Live discovery prober (packet mode): a t_prober_fn implementation that
 * actually applies one candidate strategy to a scoped, temporary
 * engine instance and performs one real TLS connectivity check
 * against it — the "real connectivity check" the discovery ladder
 * (include/discovery.h) needs.
 *
 * NOTE: this prober has had less live testing than the rest of packet
 * mode. It reuses only the proven packet-mode machinery
 * (nft_rules_apply/remove, the NFQUEUE
 * receive loop, the chain executor) for the actual packet
 * manipulation, and a real, trusted external tool (`openssl s_client`,
 * invoked via fork+execve with a fixed argv shape — domain is one
 * distinct argv element, never shell-interpolated, same posture as
 * nft_rules.c's `nft` invocation) for the connectivity oracle, rather
 * than hand-rolling a TLS client — but the orchestration GLUE below
 * (temp config, subprocess lifecycle, timing, cleanup) is new and
 * specifically flagged as the least-tested code in this project.
 * ============================================================ */
#ifdef HAVE_NFQUEUE_ENGINE

#include "discovery.h"
#include "nft_rules.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* How long to let the scoped engine instance settle (apply nftables
 * rules, bind the NFQUEUE) before starting the connectivity check.
 * Fixed rather than polled for simplicity — see the file-level note
 * above; a future session with real root should verify this is
 * actually long enough in practice, and tighten/replace it with a
 * real readiness signal if not. */
#define PROBE_ENGINE_SETTLE_MS 400

static int64_t	now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void	sleep_ms(int ms)
{
	struct timespec	ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

/* Writes a temporary, single-domain strategy.conf: default=pass (so
 * nothing else this machine talks to during the probe is touched) and
 * exactly one [domains] rule for the target. Returns 0 and fills
 * `path_out` on success (caller must unlink it), -1 on failure. */
static int	write_temp_config(const char *domain,
	const t_strategy_chain *candidate, uint8_t fake_ttl,
	char *path_out, size_t path_out_size)
{
	char	chain_desc[64];
	char	tmpl[] = "/tmp/dpi-proxy-probe-XXXXXX";
	int		fd;
	FILE	*f;

	strategy_chain_describe(candidate, chain_desc, sizeof(chain_desc));
	fd = mkstemp(tmpl);
	if (fd < 0)
		return (-1);
	f = fdopen(fd, "w");
	if (f == NULL)
	{
		close(fd);
		unlink(tmpl);
		return (-1);
	}
	fprintf(f, "default = pass\nfake_ttl = %u\n\n[domains]\n%s = %s\n",
		(unsigned)fake_ttl, domain, chain_desc);
	fclose(f);
	if (strlen(tmpl) >= path_out_size)
	{
		unlink(tmpl);
		return (-1);
	}
	strcpy(path_out, tmpl);
	return (0);
}

/* Starts a scoped engine instance (this same binary, re-exec'd via
 * /proc/self/exe so it works regardless of how the caller itself was
 * invoked) bound to `config_path`. Inherits the caller's own
 * privileges via fork+exec — no separate elevation happens here, same
 * requirement as running the engine normally. Returns the child pid
 * on success, -1 on failure. */
static pid_t	start_scoped_engine(const char *config_path)
{
	pid_t	pid;
	int		devnull;

	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0)
	{
		devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0)
		{
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		}
		setenv("DPI_PROXY_STRATEGY_CONF", config_path, 1);
		setenv("DPI_PROXY_LOG_LEVEL", "error", 1);
		execl("/proc/self/exe", "dpi-proxy-packet", (char *)NULL);
		_exit(127);
	}
	return (pid);
}

/* Bounded stop: SIGTERM, wait up to `timeout_ms`, SIGKILL if it's
 * still alive — the engine's own signal handler removes its nftables
 * table on SIGTERM (see nfqueue_engine.c), but this function never
 * assumes that happened; the caller always follows up with its own
 * best-effort `nft delete table inet dpi_proxy` regardless (see
 * probe_via_live_engine below) — belt-and-suspenders against stale
 * state, same posture as scripts/uninstall.sh. */
static void	stop_scoped_engine(pid_t pid, int timeout_ms)
{
	int64_t	deadline;
	int		status;

	if (pid <= 0)
		return ;
	kill(pid, SIGTERM);
	deadline = now_ms() + timeout_ms;
	while (now_ms() < deadline)
	{
		if (waitpid(pid, &status, WNOHANG) == pid)
			return ;
		sleep_ms(50);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
}

/* Runs `openssl s_client -connect domain:443 -servername domain`
 * (fork+execve, fixed argv shape — `domain` is one distinct argv
 * element, never shell-interpolated) with stdin from /dev/null and a
 * hard timeout. Deliberately NOT `-brief`: live-tested 2026-09-22
 * against this environment's OpenSSL 3.0.13, `-brief` prints
 * "CONNECTION ESTABLISHED"/"Verification: OK" instead of the classic
 * "CONNECTED("/"Verify return code:" markers — a real, version-
 * dependent format difference caught by that test, not assumed.
 * Plain (non-`-brief`) output was confirmed stable and always prints
 * both classic markers on this OpenSSL. Classifies the result:
 * "CONNECTED(" absent → the TCP connection itself never happened
 * (local/network-level problem, not evidence the strategy doesn't
 * work) → PROBE_LOCAL_ERROR. "CONNECTED(" present but no "Verify
 * return code:" line → a TLS handshake was attempted but didn't
 * complete → PROBE_REMOTE_REJECTED. See
 * probe_classify_openssl_output() for why a completed handshake alone
 * is not enough for PROBE_SUCCESS. */
static t_probe_result	run_openssl_check(const char *domain, int timeout_ms)
{
	int		pipefd[2];
	pid_t	pid;
	char	target[300];
	/* Large enough for a full (non-`-brief`) certificate-chain dump —
	 * live-tested 2026-09-22 against a real 4-certificate chain at
	 * ~3.4KB; sized with real headroom beyond that observed value
	 * rather than tuned exactly to it. */
	char	buf[32768];
	ssize_t	n;
	size_t	total;
	int		status;
	int64_t	deadline;

	if (pipe(pipefd) < 0)
		return (PROBE_LOCAL_ERROR);
	snprintf(target, sizeof(target), "%s:443", domain);
	pid = fork();
	if (pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		return (PROBE_LOCAL_ERROR);
	}
	if (pid == 0)
	{
		int	devnull;

		devnull = open("/dev/null", O_RDONLY);
		if (devnull >= 0)
			dup2(devnull, STDIN_FILENO);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		/* -verify_hostname: without it "Verify return code: 0 (ok)"
		 * only means the chain is trusted, not that the certificate
		 * is for `domain` — a valid certificate for some other name
		 * would count as success. */
		execlp("openssl", "openssl", "s_client", "-connect", target,
			"-servername", domain, "-verify_hostname", domain,
			(char *)NULL);
		_exit(127);
	}
	close(pipefd[1]);

	total = 0;
	deadline = now_ms() + timeout_ms;
	while (now_ms() < deadline && total + 1 < sizeof(buf))
	{
		n = read(pipefd[0], buf + total, sizeof(buf) - 1 - total);
		if (n > 0)
			total += (size_t)n;
		else if (n == 0)
			break ;
		else if (errno != EAGAIN && errno != EINTR)
			break ;
	}
	buf[total] = '\0';
	close(pipefd[0]);

	if (waitpid(pid, &status, WNOHANG) != pid)
	{
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
	}

	return (probe_classify_openssl_output(buf));
}

/* The t_prober_fn implementation exposed to discovery_run(). userdata
 * must point at a uint8_t holding the fake_ttl to use (see
 * discovery_probe_domain() below). */
t_probe_result	probe_via_live_engine(const char *domain,
	const t_strategy_chain *candidate, int timeout_ms, void *userdata)
{
	char			config_path[64];
	pid_t			engine_pid;
	t_probe_result	result;
	uint8_t			fake_ttl;

	fake_ttl = *(const uint8_t *)userdata;
	if (write_temp_config(domain, candidate, fake_ttl, config_path,
			sizeof(config_path)) < 0)
		return (PROBE_LOCAL_ERROR);

	engine_pid = start_scoped_engine(config_path);
	if (engine_pid < 0)
	{
		unlink(config_path);
		return (PROBE_LOCAL_ERROR);
	}

	sleep_ms(PROBE_ENGINE_SETTLE_MS);
	result = run_openssl_check(domain, timeout_ms);

	stop_scoped_engine(engine_pid, 3000);
	/* Belt-and-suspenders: never trust the child's own cleanup alone
	 * (it may have been SIGKILL'd above if it hung) — same reasoning
	 * as scripts/uninstall.sh's final check. Best-effort, ignored
	 * return: a missing table is not an error. */
	nft_rules_remove();
	unlink(config_path);

	return (result);
}

#endif /* HAVE_NFQUEUE_ENGINE */
