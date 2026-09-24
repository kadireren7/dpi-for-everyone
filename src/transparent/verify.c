#define _GNU_SOURCE
#include "tpd.h"
#include "compat.h"
#include "discovery.h"
#include "relay.h"
#include "tlsclient.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

/* ============================================================
 * The verifier: an ordinary TLS handshake with certificate and
 * hostname verification (OpenSSL, system trust store), carried over
 * exactly the step being judged — the step's address, on a socket
 * the platform layer keeps out of the interception, with the step's
 * ClientHello treatment (relay_send_first) on the first flight. Only
 * a handshake whose certificate verifies for the host counts.
 *
 * One thread, a small bounded queue, and a dedup window: a busy
 * browser can't turn this into a burst of handshakes.
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

static void	*g_ctx;

/* completed handshake + valid certificate: SUCCESS; completed with a
 * certificate that doesn't verify for the host (e.g. an ISP block
 * page answering for a poisoned address): REMOTE_REJECTED; no
 * handshake at all (reset, timeout): TIMEOUT — which is not evidence
 * about the certificate either way */
static t_probe_result	verify_job(const t_tpd_verify_job *job)
{
	int				fd;
	t_tlsc			*t;
	t_tlsc_result	r;

	fd = tpd_connect((const struct sockaddr *)&job->addr, job->addr_len,
			TP_CONNECT_TIMEOUT_MS);
	if (fd < 0)
		return (PROBE_TIMEOUT);
	t = tlsc_handshake(g_ctx, fd, job->host,
			relay_split_for(job->step.strategy),
			compat_now_ms() + VERIFY_TIMEOUT_MS, 0, &r);
	tlsc_free(t);
	if (r == TLSC_OK)
		return (PROBE_SUCCESS);
	if (r == TLSC_BAD_CERT)
		return (PROBE_REMOTE_REJECTED);
	return (PROBE_TIMEOUT);
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
		tpd_quic_block_sockaddr(&job->addr);
		tpd_quic_block_sockaddr(&job->original);
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

	g_ctx = tlsc_ctx_new(NULL);
	if (g_ctx == NULL)
	{
		tpd_log("[verify] cannot set up TLS (no system trust store?)");
		return (-1);
	}
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 256 * 1024);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, verifier_main, NULL);
	pthread_attr_destroy(&attr);
	return (rc == 0 ? 0 : -1);
}
