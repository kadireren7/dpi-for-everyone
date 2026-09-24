#ifndef STRATEGY_H
# define STRATEGY_H

# include <stddef.h>
# include <stdint.h>

typedef enum e_strategy
{
	STRATEGY_PASS = 0,
	STRATEGY_SPLIT,
	STRATEGY_DISORDER,
	STRATEGY_FAKE,
	STRATEGY_FRAGMENT,
	/* TLS record fragmentation ("tlsrec"): the ClientHello re-framed as
	 * two TLS records. Stream-level only — executed by the transparent
	 * daemon (dpi-proxyd) and the SOCKS proxy, never by packet mode,
	 * whose chain executor falls back to plain ACCEPT for it. */
	STRATEGY_TLSREC,
	/* TLSREC, then the re-framed bytes cut into two TCP segments
	 * right after byte 3 (transparent mode only) */
	STRATEGY_TLSREC_SPLIT
}	t_strategy;

# define STRATEGY_MAX_DOMAINS 256
# define STRATEGY_DOMAIN_MAX 256

/* A chain is an ordered list of primitive actions applied to one
 * flow's classifying packet. Kept small and fixed-size on purpose —
 * see docs/packet-mode.md for exactly which
 * combinations are in the safe whitelist (strategy_chain_is_safe)
 * and why; nothing outside that whitelist is ever accepted by
 * strategy_chain_from_string(). */
# define STRATEGY_CHAIN_MAX 2

typedef struct s_strategy_chain
{
	t_strategy	actions[STRATEGY_CHAIN_MAX];
	size_t		action_count;
}	t_strategy_chain;

typedef struct s_strategy_rule
{
	char				domain[STRATEGY_DOMAIN_MAX];
	t_strategy_chain	chain;
}	t_strategy_rule;

typedef struct s_strategy_config
{
	t_strategy		default_strategy;
	t_strategy_rule	rules[STRATEGY_MAX_DOMAINS];
	size_t			rule_count;
	/* IPv4-only, applied to FAKE decoy packets only (see
	 * packet_make_fake_tcp_v4). Configurable via a `fake_ttl = N`
	 * top-level config line (outside [domains]) or the
	 * DPI_PROXY_FAKE_TTL env var, which wins if both are present —
	 * see load_strategy_config() in nfqueue_engine.c. */
	uint8_t			fake_ttl;
}	t_strategy_config;

# define STRATEGY_DEFAULT_FAKE_TTL 8

void		strategy_config_init(t_strategy_config *cfg);

/* Parses the conceptual
 *   default = pass
 *   fake_ttl = 8
 *   [domains]
 *   example.com = pass
 *   discord.com = split+fake
 * format. Never fails outright: any malformed or unrecognized line is
 * skipped (fail-safe), and `cfg->default_strategy` stays STRATEGY_PASS
 * unless a *valid* "default = <strategy>" line overrides it. A domain
 * value may be a single strategy name or a '+'-joined chain from the
 * safe whitelist (strategy_chain_is_safe) — anything else (unknown
 * name, too many actions, disallowed combination) is skipped exactly
 * like an unknown single strategy name today. Returns the number of
 * lines skipped as malformed/unrecognized. */
size_t		strategy_config_parse(t_strategy_config *cfg,
				const char *text, size_t text_len);

/* Single-action view for callers that only care about the primary
 * action (existing behavior, unchanged for single-action configs):
 * returns the resolved chain's first action, or cfg->default_strategy
 * if no rule matches. */
t_strategy	strategy_for_domain(const t_strategy_config *cfg,
				const char *domain);

/* Full chain for a domain: exact rule first, then longest-match
 * suffix rule, then a synthetic one-action chain built from
 * cfg->default_strategy. Same precedence as strategy_for_domain. */
void		strategy_chain_for_domain(const t_strategy_config *cfg,
				const char *domain, t_strategy_chain *out);

/* Like strategy_chain_for_domain(), but distinguishes "an explicit
 * domain rule matched" (returns 1, `out` filled) from "fell through
 * to the default" (returns 0, `out` untouched) — used by callers that
 * need to know whether a manual config rule exists at all, e.g. the
 * discovery CLI's "manual override always wins" precedence
 * (see docs/discovery.md). */
int			strategy_has_explicit_rule(const t_strategy_config *cfg,
				const char *domain, t_strategy_chain *out);

const char	*strategy_name(t_strategy s);
int			strategy_from_name(const char *name, t_strategy *out);

/* True if `chain` is one of the explicitly supported safe
 * combinations: any single action, or {fake,split}, {split,fake},
 * {split,disorder}. strategy_chain_from_string() normalizes
 * {split,disorder} to plain {disorder} before this check ever runs
 * — DISORDER's only
 * correct construction already *is* split-then-reorder, so that
 * combination has no distinct safe meaning beyond plain DISORDER. */
int			strategy_chain_is_safe(const t_strategy_chain *chain);

/* Parses a domain value like "split", "fake+split", or "split+fake"
 * into `out`. Returns 0 on success (out fully populated and safe per
 * strategy_chain_is_safe), -1 on any failure (unknown action name,
 * more than STRATEGY_CHAIN_MAX actions, or a combination not in the
 * whitelist) — `out` is left unmodified on failure. */
int			strategy_chain_from_string(const char *s, t_strategy_chain *out);

/* Renders a chain back to its canonical "a+b" form for logging, e.g.
 * "split+fake". Truncates safely if buf_size is too small. */
void		strategy_chain_describe(const t_strategy_chain *chain,
				char *buf, size_t buf_size);

#endif
