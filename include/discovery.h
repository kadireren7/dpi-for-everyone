#ifndef DISCOVERY_H
# define DISCOVERY_H

# include "strategy.h"
# include "netfingerprint.h"
# include <stddef.h>
# include <stdint.h>

/* ============================================================
 * Automatic strategy discovery (packet mode): given a domain, try a fixed,
 * ordered ladder of candidate strategies, cache whichever one first
 * proves it works, and prefer that cached choice on the same network
 * until it expires or the network changes. See
 * docs/discovery.md for the user-facing reference and the design
 * rationale
 * (in particular: why probing is CLI-triggered rather than an
 * always-on background loop, which is what keeps this safe from
 * hammering hosts or looping forever by construction, not just by
 * bounded-retry policy).
 * ============================================================ */

typedef enum e_probe_result
{
	PROBE_SUCCESS = 0,
	/* The candidate strategy was applied correctly (locally), but the
	 * connection still didn't succeed within the timeout — could mean
	 * the remote/DPI rejected it, or just an unrelated network hiccup;
	 * this project cannot always tell those apart, so it's reported
	 * as one outcome rather than a false-confident guess. */
	PROBE_REMOTE_REJECTED,
	/* Something on THIS machine prevented the probe from running at
	 * all (couldn't build the candidate packet, couldn't apply
	 * nftables rules, subprocess failed to start, ...) — never
	 * treated as evidence the strategy doesn't work, and never
	 * written to the on-disk cache (see discovery_cache_set). */
	PROBE_LOCAL_ERROR,
	PROBE_TIMEOUT
}	t_probe_result;

const char	*probe_result_name(t_probe_result r);

/* The fixed, ordered candidate ladder — exactly the strategies/chains
 * this project has real behavior for (see docs/packet-mode.md), from
 * least to most invasive. Not user-configurable: the whole point is a
 * short, deliberately curated list, never a brute-force combinatorial
 * search (see task requirements — "do not blindly brute-force every
 * combination"). */
# define DISCOVERY_LADDER_LEN 7
extern const t_strategy_chain	g_discovery_ladder[DISCOVERY_LADDER_LEN];

/* Bounded-retry policy shared by every discovery run: at most this
 * many attempts per candidate (never unbounded retry), and the whole
 * ladder is walked at most once per discovery_run() call — there is
 * no background loop that could re-walk it on its own; see the
 * module comment above. */
# define DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE 2

/* Caller-supplied probe function: attempts to actually validate
 * `candidate` against `domain` (real implementation: apply the
 * candidate strategy and perform one real connectivity check, see
 * src/discovery/probe_runner.c; test implementation: a mock). Must
 * respect `timeout_ms` and must never block indefinitely. */
typedef t_probe_result (*t_prober_fn)(const char *domain,
			const t_strategy_chain *candidate, int timeout_ms,
			void *userdata);

/* Walks g_discovery_ladder in order, calling `prober` for each
 * candidate (up to DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE times on a
 * non-SUCCESS result) and stopping at the first PROBE_SUCCESS — "pick
 * the simplest working strategy" is satisfied by construction, since
 * the ladder is walked least-to-most-invasive and this stops at the
 * first success rather than continuing to search. Returns 1 and
 * fills `out_chain` if some candidate succeeded; returns 0 (out_chain
 * untouched) if the whole ladder was exhausted without a PROBE_SUCCESS.
 * `out_last_result`, if non-NULL, receives the final candidate's
 * result (useful for distinguishing "every candidate was cleanly
 * rejected" from "the probe itself couldn't run" when the return is
 * 0). Never retries more than
 * DISCOVERY_LADDER_LEN * DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE times
 * total — a hard, easily-audited bound. */
int	discovery_run(const char *domain, t_prober_fn prober, void *userdata,
		int timeout_ms, t_strategy_chain *out_chain,
		t_probe_result *out_last_result);

/* Real t_prober_fn implementation — only built into dpi-proxy-packet
 * (src/discovery/probe_runner.c, gated on HAVE_NFQUEUE_ENGINE same as
 * the rest of packet mode). `userdata` must point at a uint8_t
 * holding the fake_ttl to use for any FAKE action in `candidate`. See
 * probe_runner.c's file-level comment for exactly what is and isn't
 * live-validated about this specific function. */
t_probe_result	probe_via_live_engine(const char *domain,
			const t_strategy_chain *candidate, int timeout_ms,
			void *userdata);

/* Classifies `openssl s_client` output (non-`-brief`) for the live
 * prober: no "CONNECTED(" → PROBE_LOCAL_ERROR; a handshake that didn't
 * finish, or finished with any certificate that doesn't verify for
 * the requested name ("Verify return code:" other than "0 (ok)") →
 * PROBE_REMOTE_REJECTED; only a verified handshake → PROBE_SUCCESS.
 * The verify result matters: an ISP block page that intercepts the
 * connection presents its own (e.g. self-signed) certificate and
 * completes a handshake, which must never be cached as "this strategy
 * works". */
t_probe_result	probe_classify_openssl_output(const char *out);

/* ---- cache ---- */

# define DISCOVERY_CACHE_MAX 256
# define DISCOVERY_CACHE_DEFAULT_TTL_SECONDS (24 * 3600)

typedef struct s_discovery_cache_entry
{
	char				domain[STRATEGY_DOMAIN_MAX];
	t_strategy_chain	chain;
	uint64_t			fingerprint;
	int64_t				validated_at;
}	t_discovery_cache_entry;

typedef struct s_discovery_cache
{
	t_discovery_cache_entry	entries[DISCOVERY_CACHE_MAX];
	size_t					count;
}	t_discovery_cache;

void	discovery_cache_init(t_discovery_cache *cache);

/* Only PROBE_SUCCESS outcomes are ever persisted — a failed/undecided
 * discovery run is never written to the cache at all (see
 * PROBE_LOCAL_ERROR's own doc comment above), so there is no separate
 * "known failing" cache state to keep from going stale; the next
 * discovery_run() for that domain just starts fresh. Duplicate-domain
 * semantics match strategy_config_parse()'s set_domain_rule(): last
 * write wins, overwriting in place rather than appending. Returns 0
 * on success, -1 if the cache is full and `domain` is new. */
int		discovery_cache_set(t_discovery_cache *cache, const char *domain,
			const t_strategy_chain *chain, uint64_t fingerprint,
			int64_t now);

/* Returns the entry for `domain` only if it exists, its fingerprint
 * matches `current_fingerprint` exactly, AND it's younger than
 * `ttl_seconds` — any mismatch on any of those three is "needs
 * reprobe", returned as NULL, never a stale/wrong answer. Also
 * returns NULL (never a false match) if `current_fingerprint` is
 * NETFP_UNKNOWN — an unknown network is never assumed stable enough
 * to trust a cached result on. */
const t_discovery_cache_entry	*discovery_cache_lookup(
			const t_discovery_cache *cache, const char *domain,
			uint64_t current_fingerprint, int64_t ttl_seconds,
			int64_t now);

/* Text (de)serialization, same line-oriented, tolerant-of-malformed-
 * lines philosophy as strategy_config_parse(): one entry per line,
 * "domain fingerprint validated_at chain", '#'/';' comments and blank
 * lines ignored, malformed lines skipped (never fatal). Returns the
 * number of lines skipped on parse. */
size_t	discovery_cache_parse(t_discovery_cache *cache, const char *text,
			size_t text_len);
size_t	discovery_cache_serialize(const t_discovery_cache *cache, char *out,
			size_t out_size);

/* Bounded file wrappers around discovery_cache_parse()/_serialize(),
 * shared by the CLI (--probe/--show-strategy/--status) and the live
 * engine so both always read the exact same on-disk format. Load
 * always re-initializes `cache` first; a missing file is not an error
 * (returns 0, cache stays empty). Load returns -1 only if the file
 * exists but can't be read. Save returns 0 on success, -1 on
 * failure. */
int		discovery_cache_load_file(t_discovery_cache *cache, const char *path);
int		discovery_cache_save_file(const t_discovery_cache *cache,
			const char *path);

/* ---- runtime selection ---- */

typedef enum e_strategy_source
{
	STRATEGY_SOURCE_MANUAL = 0,
	STRATEGY_SOURCE_AUTO,
	STRATEGY_SOURCE_DEFAULT
}	t_strategy_source;

const char	*strategy_source_name(t_strategy_source s);

/* The one precedence rule every caller (live engine, --show-strategy)
 * must use: an explicit strategy.conf rule always wins, then a fresh,
 * same-network discovery cache entry (discovery_cache_lookup with
 * DISCOVERY_CACHE_DEFAULT_TTL_SECONDS), then cfg->default_strategy.
 * `cache` may be NULL (treated as empty). `entry_out`, if non-NULL,
 * receives the matching cache entry for STRATEGY_SOURCE_AUTO and NULL
 * otherwise. */
t_strategy_source	strategy_resolve_chain(const t_strategy_config *cfg,
			const t_discovery_cache *cache, uint64_t fingerprint,
			int64_t now, const char *domain, t_strategy_chain *out,
			const t_discovery_cache_entry **entry_out);

#endif
