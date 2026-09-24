#ifndef FLOW_H
# define FLOW_H

# include <stddef.h>
# include <stdint.h>
# include "strategy.h"

/* Fixed capacity by design: an NFQUEUE-fed table must never grow
 * unbounded under a flood of new connections. When full, the oldest
 * entry is evicted to make room (see flow_lookup_or_create). */
# define FLOW_TABLE_MAX 4096
# define FLOW_DEFAULT_TIMEOUT_SECONDS 30
# define FLOW_REASSEMBLY_CAP 16384

typedef enum e_flow_class
{
	FLOW_UNCLASSIFIED = 0,
	FLOW_HTTP,
	FLOW_TLS,
	FLOW_PASSTHROUGH
}	t_flow_class;

typedef struct s_flow_key
{
	uint8_t		family;
	uint8_t		src_addr[16];
	uint8_t		dst_addr[16];
	uint16_t	src_port;
	uint16_t	dst_port;
}	t_flow_key;

typedef struct s_flow_entry
{
	int			in_use;
	t_flow_key	key;
	t_flow_class	class_hint;
	uint8_t		reasm[FLOW_REASSEMBLY_CAP];
	size_t		reasm_len;
	int64_t		created_at;
	int64_t		last_seen;
	/* Set once classification has reached a terminal result (host
	 * found, or definitively not HTTP/TLS) — no more bytes need to be
	 * buffered for this flow. */
	int			classification_done;
	/* Strategy decided once, on the classifying packet (see
	 * strategy_decided) — later packets of the same flow read this
	 * instead of re-resolving strategy_for_domain()/
	 * strategy_chain_for_domain() against the config every time.
	 * Meaningless while strategy_decided is 0. `strategy` is always
	 * `chain.actions[0]` (kept alongside for existing callers/logging
	 * that only want the primary action). */
	int					strategy;
	t_strategy_chain	chain;
	int			strategy_decided;
	/* In-order-only reassembly guard (see flow_seq_is_next): the
	 * first data segment seeds next_seq, and only a segment whose
	 * seq exactly matches it advances the buffer — a retransmit
	 * (same seq again) or an out-of-order segment is rejected rather
	 * than corrupting flow->reasm by appending it at the wrong
	 * position or twice. */
	uint32_t	next_seq;
	int			seq_initialized;
}	t_flow_entry;

typedef struct s_flow_table
{
	t_flow_entry	entries[FLOW_TABLE_MAX];
	size_t			live_count;
}	t_flow_table;

void			flow_table_init(t_flow_table *table);
int				flow_key_equal(const t_flow_key *a, const t_flow_key *b);

/* Finds the live flow matching `key`, or creates one (evicting the
 * least-recently-seen entry if the table is at FLOW_TABLE_MAX).
 * Always succeeds — returns NULL only if `table` is NULL. */
t_flow_entry	*flow_lookup_or_create(t_flow_table *table,
					const t_flow_key *key, int64_t now);

/* Removes every entry whose last_seen is older than `timeout_seconds`
 * relative to `now`. Returns the number of entries evicted. */
size_t			flow_evict_expired(t_flow_table *table, int64_t now,
					int64_t timeout_seconds);

/* Appends `len` bytes to the flow's reassembly buffer, bounded by
 * FLOW_REASSEMBLY_CAP. Returns 0 on success, -1 if it would overflow
 * the cap (caller should treat the flow as unclassifiable and PASS). */
int				flow_reasm_append(t_flow_entry *flow, const uint8_t *data,
					size_t len);

/* True (and advances flow->next_seq) only if `seq` is exactly the
 * next byte this flow expects — the first non-empty segment always
 * passes and seeds the baseline. False for a retransmit (seq already
 * seen) or an out-of-order segment (seq ahead of what's expected);
 * the caller should not append that segment's payload to reasm. A
 * zero-length segment is never "next" (nothing to advance past) but
 * doesn't count as a gap either. */
int				flow_seq_is_next(t_flow_entry *flow, uint32_t seq,
					size_t payload_len);

/* Wipes `flow` back to a freshly-created state for the same key —
 * used when a new connection (a bare SYN) reuses a 4-tuple the table
 * still holds, so the new connection's ClientHello is classified and
 * gets its own strategy decision instead of inheriting the old
 * connection's classification_done/strategy. */
void			flow_restart(t_flow_entry *flow, int64_t now);

/* Clears the cached per-flow strategy decision (strategy_decided,
 * strategy, chain) on every live flow, e.g. after the strategy config
 * or discovery cache was reloaded, so no flow keeps reporting a
 * decision made against the old config. Returns how many flows had a
 * decision cleared. */
size_t			flow_invalidate_decisions(t_flow_table *table);

#endif
