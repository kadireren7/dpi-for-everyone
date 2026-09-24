#include "flow.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static t_flow_key	make_key(uint16_t src_port, uint16_t dst_port)
{
	t_flow_key	key;

	memset(&key, 0, sizeof(key));
	key.family = 4;
	key.src_addr[0] = 10;
	key.dst_addr[0] = 20;
	key.src_port = src_port;
	key.dst_port = dst_port;
	return (key);
}

static void	test_lookup_creates_and_reuses(void)
{
	static t_flow_table	table;
	t_flow_key		key;
	t_flow_entry	*a;
	t_flow_entry	*b;

	flow_table_init(&table);
	key = make_key(1000, 443);

	a = flow_lookup_or_create(&table, &key, 100);
	assert(a != NULL);
	assert(table.live_count == 1);

	b = flow_lookup_or_create(&table, &key, 105);
	assert(a == b);
	assert(b->last_seen == 105);
	assert(table.live_count == 1);
}

static void	test_different_keys_are_different_flows(void)
{
	static t_flow_table	table;
	t_flow_key		k1;
	t_flow_key		k2;
	t_flow_entry	*a;
	t_flow_entry	*b;

	flow_table_init(&table);
	k1 = make_key(1000, 443);
	k2 = make_key(1001, 443);

	a = flow_lookup_or_create(&table, &k1, 1);
	b = flow_lookup_or_create(&table, &k2, 1);
	assert(a != b);
	assert(table.live_count == 2);
}

static void	test_expiry(void)
{
	static t_flow_table	table;
	t_flow_key		key;
	size_t			evicted;

	flow_table_init(&table);
	key = make_key(2000, 80);
	flow_lookup_or_create(&table, &key, 0);

	evicted = flow_evict_expired(&table, 10, FLOW_DEFAULT_TIMEOUT_SECONDS);
	assert(evicted == 0);
	assert(table.live_count == 1);

	evicted = flow_evict_expired(&table, 1000, FLOW_DEFAULT_TIMEOUT_SECONDS);
	assert(evicted == 1);
	assert(table.live_count == 0);
}

static void	test_table_stays_bounded_under_flood(void)
{
	static t_flow_table	table;
	t_flow_key		key;
	size_t			i;

	flow_table_init(&table);
	i = 0;
	while (i < FLOW_TABLE_MAX + 50)
	{
		key = make_key((uint16_t)(1000 + (i % 60000)), 443);
		key.src_addr[1] = (uint8_t)(i >> 8);
		key.src_addr[2] = (uint8_t)i;
		flow_lookup_or_create(&table, &key, (int64_t)i);
		i++;
	}
	assert(table.live_count <= FLOW_TABLE_MAX);
}

static void	test_strategy_cache_defaults_and_persists(void)
{
	static t_flow_table	table;
	t_flow_key			key;
	t_flow_entry		*flow;

	flow_table_init(&table);
	key = make_key(4000, 443);
	flow = flow_lookup_or_create(&table, &key, 1);

	/* A fresh flow has no cached strategy decision yet. */
	assert(flow->strategy_decided == 0);

	flow->strategy = 42;
	flow->strategy_decided = 1;

	/* Looking the same flow up again must return the same entry with
	 * the cached decision intact, not a freshly reset one. */
	flow = flow_lookup_or_create(&table, &key, 2);
	assert(flow->strategy_decided == 1);
	assert(flow->strategy == 42);
}

static void	test_seq_tracking_rejects_duplicate_and_out_of_order(void)
{
	t_flow_entry	flow;

	memset(&flow, 0, sizeof(flow));

	/* First segment always seeds the baseline. */
	assert(flow_seq_is_next(&flow, 1000, 100) == 1);
	assert(flow.next_seq == 1100);

	/* Exact retransmit of the same segment: rejected, not re-applied. */
	assert(flow_seq_is_next(&flow, 1000, 100) == 0);
	assert(flow.next_seq == 1100);

	/* Out-of-order (ahead of what's expected): rejected. */
	assert(flow_seq_is_next(&flow, 1300, 50) == 0);
	assert(flow.next_seq == 1100);

	/* The actually-expected next segment: accepted, advances. */
	assert(flow_seq_is_next(&flow, 1100, 200) == 1);
	assert(flow.next_seq == 1300);

	/* Zero-length segment (e.g. a pure ACK) is never "next". */
	assert(flow_seq_is_next(&flow, 1300, 0) == 0);
	assert(flow.next_seq == 1300);
}

static void	test_reasm_append_bounded(void)
{
	static t_flow_table	table;
	t_flow_key		key;
	t_flow_entry	*flow;
	uint8_t			chunk[1024];

	memset(chunk, 'x', sizeof(chunk));
	flow_table_init(&table);
	key = make_key(3000, 443);
	flow = flow_lookup_or_create(&table, &key, 1);

	while (flow->reasm_len + sizeof(chunk) <= FLOW_REASSEMBLY_CAP)
		assert(flow_reasm_append(flow, chunk, sizeof(chunk)) == 0);

	assert(flow_reasm_append(flow, chunk, sizeof(chunk)) == -1);
}

/* A new connection (bare SYN) on a 4-tuple the table still holds must
 * not inherit the old connection's "already classified, PASS" state,
 * or its ClientHello is never classified and it stays on PASS. */
static void	test_restart_clears_stale_classification(void)
{
	static t_flow_table	table;
	t_flow_key			key;
	t_flow_entry		*flow;
	const uint8_t		data[4] = {1, 2, 3, 4};

	flow_table_init(&table);
	key = make_key(5000, 443);
	flow = flow_lookup_or_create(&table, &key, 10);
	assert(flow_seq_is_next(flow, 100, sizeof(data)));
	flow_reasm_append(flow, data, sizeof(data));
	flow->classification_done = 1;
	flow->strategy_decided = 1;
	flow->strategy = STRATEGY_PASS;

	flow_restart(flow, 20);
	assert(table.live_count == 1);
	assert(flow->in_use == 1);
	assert(flow_key_equal(&flow->key, &key));
	assert(flow->classification_done == 0);
	assert(flow->strategy_decided == 0);
	assert(flow->reasm_len == 0);
	assert(flow->seq_initialized == 0);
	assert(flow->last_seen == 20);
	assert(flow_lookup_or_create(&table, &key, 21) == flow);
}

/* Reload must not leave any flow reporting a decision made against
 * the old config. */
static void	test_invalidate_decisions_after_reload(void)
{
	static t_flow_table	table;
	t_flow_key			key_a;
	t_flow_key			key_b;
	t_flow_entry		*a;
	t_flow_entry		*b;

	flow_table_init(&table);
	key_a = make_key(6000, 443);
	key_b = make_key(6001, 443);
	a = flow_lookup_or_create(&table, &key_a, 1);
	b = flow_lookup_or_create(&table, &key_b, 1);
	a->strategy_decided = 1;
	a->strategy = STRATEGY_SPLIT;
	a->chain.action_count = 1;
	a->chain.actions[0] = STRATEGY_SPLIT;

	assert(flow_invalidate_decisions(&table) == 1);
	assert(a->strategy_decided == 0);
	assert(a->strategy == STRATEGY_PASS);
	assert(b->strategy_decided == 0);
	assert(table.live_count == 2);
	assert(flow_invalidate_decisions(&table) == 0);
}

int	main(void)
{
	test_lookup_creates_and_reuses();
	test_different_keys_are_different_flows();
	test_expiry();
	test_table_stays_bounded_under_flood();
	test_strategy_cache_defaults_and_persists();
	test_seq_tracking_rejects_duplicate_and_out_of_order();
	test_reasm_append_bounded();
	test_restart_clears_stale_classification();
	test_invalidate_decisions_after_reload();
	printf("test_flow: OK\n");
	return (0);
}
