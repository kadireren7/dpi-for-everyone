#define _GNU_SOURCE
#include "tpd.h"
#include "common.h"
#include "discovery.h"
#include "relay.h"
#include "upstream.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

/* ============================================================
 * The verifier: an ordinary OpenSSL handshake with hostname
 * verification (`openssl s_client -verify_hostname`), carried over
 * exactly the step being judged. s_client connects to a one-shot
 * loopback listener; this thread accepts that one connection and
 * relays it with the shared relay core (relay_send_first applies the
 * step's ClientHello treatment, relay_pump_timeout copies the rest)
 * to the step's address on a marked socket. The TLS session and its
 * verification are entirely OpenSSL's; this code only moves bytes
 * and reads the "Verify return code" line (probe_classify_openssl_
 * output, shared with packet mode's prober).
 *
 * One thread, a small bounded queue, and a dedup window: a busy
 * browser can't turn this into a burst of subprocesses.
 * ============================================================ */

#define QUEUE_MAX 16
#define RECENT_MAX 128
#define RECENT_WINDOW_S 600
#define VERIFY_TIMEOUT_MS 8000

static t_tpd_verify_job	g_queue[QUEUE_MAX];
static size_t			g_queue_len;
static pthread_mutex_t	g_qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	g_qcond = PTHREAD_COND_INITIALIZER;

typedef struct s_recent
{
	char				host[STRATEGY_DOMAIN_MAX];
	t_tpd_verify_kind	kind;
	int					family;
	t_tp_step			step;
	int64_t				at;
}	t_recent;

static t_recent			g_recent[RECENT_MAX];
static size_t			g_recent_next;

static int	seen_recently(const t_tpd_verify_job *job, int64_t now)
{
	size_t	i;

	i = 0;
	while (i < RECENT_MAX)
	{
		if (g_recent[i].at != 0 && now - g_recent[i].at < RECENT_WINDOW_S
			&& g_recent[i].kind == job->kind
			&& g_recent[i].family == job->family
			&& g_recent[i].step.target == job->step.target
			&& g_recent[i].step.strategy == job->step.strategy
			&& strcasecmp(g_recent[i].host, job->host) == 0)
			return (1);
		i++;
	}
	return (0);
}

void	tpd_verify_submit(const t_tpd_verify_job *job)
{
	t_recent	*r;
	int64_t		now;

	now = tpd_now();
	pthread_mutex_lock(&g_qlock);
	if (!seen_recently(job, now) && g_queue_len < QUEUE_MAX)
	{
		g_queue[g_queue_len++] = *job;
		r = &g_recent[g_recent_next];
		g_recent_next = (g_recent_next + 1) % RECENT_MAX;
		snprintf(r->host, sizeof(r->host), "%s", job->host);
		r->kind = job->kind;
		r->family = job->family;
		r->step = job->step;
		r->at = now;
		pthread_cond_signal(&g_qcond);
	}
	pthread_mutex_unlock(&g_qlock);
}

static int	make_listener(int *port)
{
	int					fd;
	struct sockaddr_in	sin;
	socklen_t			len;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	len = sizeof(sin);
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0
		|| listen(fd, 1) < 0
		|| getsockname(fd, (struct sockaddr *)&sin, &len) < 0)
	{
		close(fd);
		return (-1);
	}
	*port = ntohs(sin.sin_port);
	return (fd);
}

static pid_t	spawn_openssl(const char *host, int port, int *out_fd)
{
	int		pipefd[2];
	pid_t	pid;
	char	target[32];
	int		devnull;

	if (pipe2(pipefd, O_CLOEXEC) < 0)
		return (-1);
	snprintf(target, sizeof(target), "127.0.0.1:%d", port);
	pid = fork();
	if (pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		return (-1);
	}
	if (pid == 0)
	{
		devnull = open("/dev/null", O_RDONLY);
		if (devnull >= 0)
			dup2(devnull, STDIN_FILENO);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		execlp("openssl", "openssl", "s_client", "-connect", target,
			"-servername", host, "-verify_hostname", host, (char *)NULL);
		_exit(127);
	}
	close(pipefd[1]);
	*out_fd = pipefd[0];
	return (pid);
}

/* Carries s_client's one connection over the job's step. */
static void	carry(int listen_fd, const t_tpd_verify_job *job)
{
	struct pollfd	pfd;
	int				local;
	int				upstream;
	unsigned char	first[BUFFER_SIZE];
	ssize_t			n;

	pfd.fd = listen_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, VERIFY_TIMEOUT_MS) <= 0)
		return ;
	local = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
	if (local < 0)
		return ;
	upstream = connect_upstream_addr((const struct sockaddr *)&job->addr,
			job->addr_len, TP_CONNECT_TIMEOUT_MS, TP_SOCKET_MARK);
	pfd.fd = local;
	if (upstream >= 0 && poll(&pfd, 1, VERIFY_TIMEOUT_MS) > 0)
	{
		n = recv(local, first, sizeof(first), 0);
		if (n > 0 && relay_send_first(upstream, first, (size_t)n,
				relay_split_for(job->step.strategy)) == 0)
			relay_pump_timeout(local, upstream, NULL, VERIFY_TIMEOUT_MS);
	}
	if (upstream >= 0)
		close(upstream);
	close(local);
}

static t_probe_result	collect(pid_t pid, int out_fd)
{
	char			buf[32768];
	size_t			total;
	ssize_t			n;
	int				status;
	struct pollfd	pfd;
	int64_t			deadline;

	deadline = tpd_now_ms() + VERIFY_TIMEOUT_MS;
	pfd.fd = out_fd;
	pfd.events = POLLIN;
	total = 0;
	while (total + 1 < sizeof(buf))
	{
		pfd.revents = 0;
		if (tpd_now_ms() >= deadline
			|| poll(&pfd, 1, (int)(deadline - tpd_now_ms())) <= 0)
			break ;
		n = read(out_fd, buf + total, sizeof(buf) - 1 - total);
		if (n < 0 && errno == EINTR)
			continue ;
		if (n <= 0)
			break ;
		total += (size_t)n;
	}
	buf[total] = '\0';
	close(out_fd);
	kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return (probe_classify_openssl_output(buf));
}

static t_probe_result	verify_job(const t_tpd_verify_job *job)
{
	int		listen_fd;
	int		port;
	int		out_fd;
	pid_t	pid;

	listen_fd = make_listener(&port);
	if (listen_fd < 0)
		return (PROBE_LOCAL_ERROR);
	pid = spawn_openssl(job->host, port, &out_fd);
	if (pid < 0)
	{
		close(listen_fd);
		return (PROBE_LOCAL_ERROR);
	}
	carry(listen_fd, job);
	close(listen_fd);
	return (collect(pid, out_fd));
}

static void	block_quic(const struct sockaddr_storage *a)
{
	char	s[INET6_ADDRSTRLEN];

	tpd_addr_str(a, s, sizeof(s));
	tp_nft_add_quic(a->ss_family == AF_INET6 ? 6 : 4, s);
}

static void	apply_result(const t_tpd_verify_job *job, t_probe_result r)
{
	char	addr[INET6_ADDRSTRLEN];
	int		current;

	tpd_addr_str(&job->addr, addr, sizeof(addr));
	pthread_mutex_lock(&g_tpd.lock);
	current = (g_tpd.fp == job->fp);
	if (r == PROBE_SUCCESS)
		g_tpd.stats.verified_ok++;
	else if (r == PROBE_REMOTE_REJECTED)
		g_tpd.stats.verified_bad++;
	if (current && job->kind == TPD_VERIFY_DIRECT
		&& r == PROBE_REMOTE_REJECTED)
		tp_direct_bad_mark(&g_tpd.dec, job->host, job->fp, job->family,
			tpd_now());
	if (current && job->kind == TPD_VERIFY_CONFIRM && r == PROBE_SUCCESS)
	{
		tp_decision_success(&g_tpd.dec, job->host, job->fp, job->family,
			tpd_now(), job->step);
		snprintf(g_tpd.last_learned, sizeof(g_tpd.last_learned),
			"%s %s+%s", job->host, tp_target_name(job->step.target),
			strategy_name(job->step.strategy));
	}
	pthread_mutex_unlock(&g_tpd.lock);
	if (!current)
		return ;
	if (job->kind == TPD_VERIFY_DIRECT && r == PROBE_REMOTE_REJECTED)
		tpd_log("[verify] %s: original address %s does not present a valid "
			"certificate for it; next connections skip DIRECT to it for %ds",
			job->host, addr, TP_DIRECT_BAD_TTL_SECONDS);
	else if (job->kind == TPD_VERIFY_CONFIRM && r == PROBE_SUCCESS)
	{
		tpd_log("[learn] %s: %s+%s via %s (certificate verified)%s",
			job->host, tp_target_name(job->step.target),
			strategy_name(job->step.strategy), addr,
			job->step.target == TP_TARGET_TRUSTED
			? " — system DNS answer looks poisoned on this network" : "");
		/* QUIC can't use this bypass: make UDP/443 to these addresses
		 * fail fast so the application falls back to TCP */
		block_quic(&job->addr);
		block_quic(&job->original);
	}
	else if (job->kind == TPD_VERIFY_CONFIRM)
		tpd_log("[verify] %s: %s+%s via %s did not verify (%s); not cached",
			job->host, tp_target_name(job->step.target),
			strategy_name(job->step.strategy), addr, probe_result_name(r));
	else
		tpd_debug("[verify] %s: direct via %s: %s", job->host, addr,
			probe_result_name(r));
}

static void	*verifier_main(void *arg)
{
	t_tpd_verify_job	job;
	t_probe_result		r;

	(void)arg;
	while (1)
	{
		pthread_mutex_lock(&g_qlock);
		while (g_queue_len == 0)
			pthread_cond_wait(&g_qcond, &g_qlock);
		job = g_queue[0];
		memmove(&g_queue[0], &g_queue[1],
			(g_queue_len - 1) * sizeof(g_queue[0]));
		g_queue_len--;
		pthread_mutex_unlock(&g_qlock);
		r = verify_job(&job);
		apply_result(&job, r);
	}
	return (NULL);
}

int	tpd_verify_start(void)
{
	pthread_t		tid;
	pthread_attr_t	attr;
	int				rc;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 256 * 1024);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, verifier_main, NULL);
	pthread_attr_destroy(&attr);
	return (rc == 0 ? 0 : -1);
}
