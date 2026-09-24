#ifndef TP_H
# define TP_H

# include "strategy.h"
# include <stddef.h>
# include <stdint.h>

/* ============================================================
 * Transparent mode (dpi-proxyd, Linux): nftables REDIRECTs outgoing
 * TCP/443 to a loopback listener, which recovers the original
 * destination (SO_ORIGINAL_DST) and the hostname (ClientHello SNI),
 * then connects out itself using the least invasive attempt that
 * gets a TLS answer:
 *
 *   manual strategy.conf rule  >  cached decision  >  ladder
 *   ladder: known-blocked host (tp_host_listed): TLSREC variants
 *              first, the network's last working one leading
 *           original address DIRECT
 *           -> only if that failed: ask the trusted resolver;
 *              if it disagrees: trusted address DIRECT
 *           -> TLSREC, TLSREC_SPLIT (TLS record fragmentation)
 *
 * DNS disagreement alone is never treated as poisoning. A bypass
 * decision is only cached after an independent, ordinary OpenSSL
 * handshake (`openssl s_client -verify_hostname`) over the very same
 * step verified the certificate for the hostname (server.c, the
 * verifier). The same check, triggered by a connection that ended
 * suspiciously (see server.c), is what marks DIRECT to the original
 * address as bad for a host (tp_direct_bad) — e.g. an ISP block host
 * handed out by poisoned system DNS.
 *
 * No TLS termination: the client's own ClientHello is forwarded (at
 * most re-framed into two TLS records) and the client verifies the
 * real server certificate itself — this never impersonates anyone.
 * The ClientHello is buffered until an attempt is committed, so a
 * failed attempt is invisible to the application.
 *
 * This header is the pure, unit-tested logic (src/transparent/
 * policy.c); src/transparent/server.c does the sockets
 * and nft.c the nftables side. See docs/transparent-mode.md.
 * ============================================================ */

/* Where an attempt connects to. */
typedef enum e_tp_target
{
	TP_TARGET_ORIGINAL = 0,	/* the address the application connected to */
	TP_TARGET_TRUSTED		/* the SNI hostname, via the trusted resolver */
}	t_tp_target;

const char	*tp_target_name(t_tp_target t);

typedef struct s_tp_step
{
	t_tp_target	target;
	t_strategy	strategy;	/* PASS (direct), TLSREC or TLSREC_SPLIT */
}	t_tp_step;

/* What one attempt ended with. Everything but OK/ALERT is a failed
 * attempt; CONNECT_FAIL is the only one that happens before our
 * ClientHello reached the network (so it says nothing about DPI). */
typedef enum e_tp_result
{
	TP_RES_OK = 0,			/* ServerHello, certificate not rejected */
	TP_RES_ALERT,			/* the server answered with a TLS alert */
	TP_RES_CONNECT_FAIL,	/* refused / unreachable / connect timeout */
	TP_RES_RESET,			/* RST after the ClientHello */
	TP_RES_CLOSED,			/* EOF after the ClientHello */
	TP_RES_TIMEOUT,			/* no answer to the ClientHello */
	TP_RES_NOT_TLS,			/* answered, but not with TLS */
	TP_RES_SKIPPED			/* known bad (direct_bad), not attempted */
}	t_tp_result;

const char	*tp_result_name(t_tp_result r);

/* Does the trusted resolver agree with the application's address? */
typedef enum e_tp_trust
{
	TP_TRUST_UNKNOWN = 0,	/* not looked up (yet) */
	TP_TRUST_NONE,			/* lookup failed / no addresses */
	TP_TRUST_MATCH,			/* original address is among the answers */
	TP_TRUST_MISMATCH		/* answers exist, original isn't one */
}	t_tp_trust;

typedef enum e_tp_source
{
	TP_SRC_NONE = 0,	/* no hostname: plain pass-through */
	TP_SRC_MANUAL,
	TP_SRC_CACHED,
	TP_SRC_LADDER,
	TP_SRC_COOLDOWN
}	t_tp_source;

const char	*tp_source_name(t_tp_source s);

# define TP_MAX_ATTEMPTS 4
# define TP_CONNECT_TIMEOUT_MS 3000
/* Wait for the first answer to our ClientHello. */
# define TP_REPLY_TIMEOUT_MS 4000

/* One connection's attempt plan. Fill the inputs, then alternate
 * tp_plan_next() / tp_plan_record() until tp_plan_next() says DONE or
 * an attempt returned OK/ALERT. */
typedef struct s_tp_plan
{
	int			has_host;
	/* the host is on the known-blocked list (tp_host_listed): its
	 * first attempts are the bypasses, not DIRECT */
	int			listed;
	/* the bypass that last worked on this network (TLSREC or
	 * TLSREC_SPLIT; anything else means TLSREC): tried first */
	t_strategy	preferred;
	int			has_manual;
	t_strategy	manual;
	int			has_cached;
	t_tp_step	cached;
	int			in_cooldown;
	/* DIRECT to the original address was verified NOT to give a valid
	 * certificate for the host recently (tp_direct_bad): skip it */
	int			direct_bad;
	t_tp_trust	trust;		/* caller updates this after NEED_DNS */
	t_tp_step	tried[TP_MAX_ATTEMPTS];
	t_tp_result	results[TP_MAX_ATTEMPTS];
	size_t		ntried;
}	t_tp_plan;

typedef enum e_tp_next
{
	TP_NEXT_ATTEMPT = 0,	/* *step / *timeout_ms filled: try it */
	TP_NEXT_NEED_DNS,		/* resolve the host, set plan->trust, ask again */
	TP_NEXT_DONE			/* nothing (more) worth trying */
}	t_tp_next;

/* Built-in list of domains that are DPI-blocked where this tool is
 * used (Discord and a few others); subdomains match. Only decides
 * which attempt comes first — never whether a host is intercepted. */
int			tp_host_listed(const char *host);

void		tp_plan_init(t_tp_plan *p);
t_tp_next	tp_plan_next(const t_tp_plan *p, t_tp_step *step,
				int *reply_timeout_ms);
void		tp_plan_record(t_tp_plan *p, t_tp_step step, t_tp_result r);
t_tp_source	tp_plan_source(const t_tp_plan *p);

/* ---- per-host decisions ---- */

/* Hosts that failed every attempt are only retried DIRECT-once until
 * this passes, so a dead or fully blocked host doesn't make every
 * connection to it walk the whole ladder again. */
# define TP_COOLDOWN_SECONDS 60
# define TP_COOLDOWN_MAX 64
# define TP_DECISION_TTL_SECONDS (24 * 3600)
# define TP_DECISIONS_MAX 2048

typedef struct s_tp_decision
{
	char		host[STRATEGY_DOMAIN_MAX];
	uint64_t	fingerprint;
	int			family;			/* 4 or 6 */
	t_tp_step	step;
	int64_t		validated_at;
	int64_t		quic_blocked_at;	/* runtime only, not persisted */
}	t_tp_decision;

typedef struct s_tp_cooldown
{
	char	host[STRATEGY_DOMAIN_MAX];
	int64_t	until;
}	t_tp_cooldown;

/* "DIRECT to the original address verified bad" marks: exact host,
 * network, family; in memory only, expire after TP_DIRECT_BAD_TTL. */
# define TP_DIRECT_BAD_MAX 128
# define TP_DIRECT_BAD_TTL_SECONDS 3600

typedef struct s_tp_mark
{
	char		host[STRATEGY_DOMAIN_MAX];
	uint64_t	fingerprint;
	int			family;
	int64_t		until;
}	t_tp_mark;

typedef struct s_tp_decisions
{
	/* grows on demand up to TP_DECISIONS_MAX (oldest evicted) — no
	 * large fixed allocation for a mostly-empty table */
	t_tp_decision	*entries;
	size_t			count;
	size_t			cap;
	t_tp_cooldown	cooldown[TP_COOLDOWN_MAX];
	t_tp_mark		direct_bad[TP_DIRECT_BAD_MAX];
	int				dirty;
}	t_tp_decisions;

void		tp_decisions_init(t_tp_decisions *d);
void		tp_decisions_free(t_tp_decisions *d);

/* Fresh decision for (host, network, family), or NULL. Never matches
 * under NETFP_UNKNOWN. */
t_tp_decision	*tp_decision_lookup(t_tp_decisions *d, const char *host,
				uint64_t fp, int family, int64_t now);

/* Records a committed connection: `step` worked. DIRECT to the
 * original address is the default and is never stored — it removes
 * any decision instead ("a destination that works directly stays
 * DIRECT"); anything else is stored (rewritten only if it changed or
 * is past half its TTL, so steady traffic doesn't rewrite the file).
 * Clears the host's cooldown. Nothing is stored under NETFP_UNKNOWN. */
void		tp_decision_success(t_tp_decisions *d, const char *host,
				uint64_t fp, int family, int64_t now, t_tp_step step);

/* Every attempt failed: starts the host's cooldown and drops its
 * (evidently wrong) decision. */
void		tp_decision_failure(t_tp_decisions *d, const char *host,
				uint64_t fp, int family, int64_t now);

int			tp_in_cooldown(const t_tp_decisions *d, const char *host,
				int64_t now);

void		tp_direct_bad_mark(t_tp_decisions *d, const char *host,
				uint64_t fp, int family, int64_t now);
int			tp_direct_bad(const t_tp_decisions *d, const char *host,
				uint64_t fp, int family, int64_t now);

/* Network changed: forget cooldowns and direct-bad marks (both are
 * about the network we just left). Cached decisions stay — they are
 * keyed by fingerprint and simply stop matching. */
void		tp_decisions_network_changed(t_tp_decisions *d);

/* "host fingerprint family strategy target validated_at" per line;
 * '#' comments, malformed lines skipped (returns how many). */
size_t		tp_decisions_parse(t_tp_decisions *d, const char *text,
				size_t len);
/* Returns bytes written, or 0 if out_size is too small. */
size_t		tp_decisions_serialize(const t_tp_decisions *d, char *out,
				size_t out_size);

/* ---- nftables ruleset ---- */

/* Owned exclusively by dpi-proxyd; distinct from packet mode's
 * "dpi_proxy" table, and never touched by anything else. */
# define TP_NFT_TABLE "dpi_proxy_tp"
/* SO_MARK on every socket dpi-proxyd opens itself (upstream TCP, DNS),
 * so its own traffic is never redirected back to it. Distinct from
 * packet mode's NFT_ANTILOOP_MARK. */
# define TP_SOCKET_MARK 0x2a4c
# define TP_DEFAULT_PORT 1091
/* Local DNS forwarder (UDP+TCP, 127.0.0.1 and [::1]). */
# define TP_DEFAULT_DNS_PORT 1053
/* Fail-open heartbeat: the redirect rule only matches ports that are
 * in the "alive" set, whose single element expires after
 * TP_ALIVE_TIMEOUT_S unless the daemon refreshes it (every
 * TP_HEARTBEAT_S). A crashed, killed or hung daemon therefore stops
 * intercepting on its own within that window, even if nothing
 * deleted the table. */
# define TP_ALIVE_TIMEOUT_S 30
# define TP_HEARTBEAT_S 10
/* How long a destination stays in the QUIC-reject set. */
# define TP_QUIC_BLOCK_TIMEOUT_S 3600

/* The whole table, as `nft -f` input (sockets that already carry any
 * mark — ours, a VPN's, another proxy's — are never intercepted):
 * deletes any previous copy of our own table first (idempotent
 * restart, stale-table recovery), then a nat/output chain that
 *   - with dns_port > 0: REDIRECTs UDP+TCP/53 to `dns_port` (any
 *     non-loopback destination, private ones included — the router's
 *     resolver is the one that lies), gated by the alive_dns set;
 *   - REDIRECTs TCP/443 to `port` (skipping loopback, private/link-
 *     local/multicast destinations), gated by the alive set;
 * and a filter/output chain that rejects UDP/443 only to addresses in
 * the quic_block4/quic_block6 sets — so QUIC falls back to TCP for
 * exactly those destinations and nothing else. With ipv6 = 0 (no
 * [::1] listeners), IPv6 is never redirected. Both alive sets start
 * empty; see tp_nft_heartbeat. Returns the length, 0 if out_size is
 * too small. */
size_t		tp_nft_ruleset(char *out, size_t out_size, int port,
				int ipv6, int dns_port);
/* Re-arms alive (443) and, with dns != 0, alive_dns (53); with
 * dns == 0 alive_dns is emptied, so DNS is left alone. */
size_t		tp_nft_heartbeat(char *out, size_t out_size, int dns);
/* `addr` is a printable IPv4/IPv6 literal (checked by the caller). */
size_t		tp_nft_quic_block(char *out, size_t out_size, int family,
				const char *addr);

#endif
