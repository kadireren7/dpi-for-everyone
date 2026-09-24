#include "flow.h"

#include <string.h>

void	flow_table_init(t_flow_table *table)
{
	memset(table, 0, sizeof(*table));
}

int	flow_key_equal(const t_flow_key *a, const t_flow_key *b)
{
	if (a->family != b->family)
		return (0);
	if (a->src_port != b->src_port || a->dst_port != b->dst_port)
		return (0);
	if (memcmp(a->src_addr, b->src_addr, sizeof(a->src_addr)) != 0)
		return (0);
	if (memcmp(a->dst_addr, b->dst_addr, sizeof(a->dst_addr)) != 0)
		return (0);
	return (1);
}

static void	flow_reset(t_flow_entry *flow, const t_flow_key *key, int64_t now)
{
	memset(flow, 0, sizeof(*flow));
	flow->in_use = 1;
	flow->key = *key;
	flow->class_hint = FLOW_UNCLASSIFIED;
	flow->created_at = now;
	flow->last_seen = now;
}

static t_flow_entry	*find_free_or_oldest(t_flow_table *table)
{
	size_t			i;
	t_flow_entry	*oldest;

	i = 0;
	while (i < FLOW_TABLE_MAX)
	{
		if (!table->entries[i].in_use)
			return (&table->entries[i]);
		i++;
	}

	oldest = &table->entries[0];
	i = 1;
	while (i < FLOW_TABLE_MAX)
	{
		if (table->entries[i].last_seen < oldest->last_seen)
			oldest = &table->entries[i];
		i++;
	}
	return (oldest);
}

t_flow_entry	*flow_lookup_or_create(t_flow_table *table,
	const t_flow_key *key, int64_t now)
{
	size_t			i;
	t_flow_entry	*slot;

	if (table == NULL || key == NULL)
		return (NULL);

	i = 0;
	while (i < FLOW_TABLE_MAX)
	{
		if (table->entries[i].in_use
			&& flow_key_equal(&table->entries[i].key, key))
		{
			table->entries[i].last_seen = now;
			return (&table->entries[i]);
		}
		i++;
	}

	slot = find_free_or_oldest(table);
	if (!slot->in_use)
		table->live_count++;
	flow_reset(slot, key, now);
	return (slot);
}

size_t	flow_evict_expired(t_flow_table *table, int64_t now,
	int64_t timeout_seconds)
{
	size_t	i;
	size_t	evicted;

	evicted = 0;
	i = 0;
	while (i < FLOW_TABLE_MAX)
	{
		if (table->entries[i].in_use
			&& now - table->entries[i].last_seen > timeout_seconds)
		{
			memset(&table->entries[i], 0, sizeof(table->entries[i]));
			table->live_count--;
			evicted++;
		}
		i++;
	}
	return (evicted);
}

int	flow_reasm_append(t_flow_entry *flow, const uint8_t *data, size_t len)
{
	if (flow->reasm_len + len > FLOW_REASSEMBLY_CAP)
		return (-1);

	memcpy(flow->reasm + flow->reasm_len, data, len);
	flow->reasm_len += len;
	return (0);
}

int	flow_seq_is_next(t_flow_entry *flow, uint32_t seq, size_t payload_len)
{
	if (payload_len == 0)
		return (0);

	if (!flow->seq_initialized)
	{
		flow->seq_initialized = 1;
		flow->next_seq = seq + (uint32_t)payload_len;
		return (1);
	}

	if (seq != flow->next_seq)
		return (0);

	flow->next_seq += (uint32_t)payload_len;
	return (1);
}

void	flow_restart(t_flow_entry *flow, int64_t now)
{
	t_flow_key	key;

	key = flow->key;
	flow_reset(flow, &key, now);
}

size_t	flow_invalidate_decisions(t_flow_table *table)
{
	size_t	i;
	size_t	cleared;

	cleared = 0;
	i = 0;
	while (i < FLOW_TABLE_MAX)
	{
		if (table->entries[i].in_use && table->entries[i].strategy_decided)
		{
			table->entries[i].strategy_decided = 0;
			table->entries[i].strategy = STRATEGY_PASS;
			table->entries[i].chain.action_count = 1;
			table->entries[i].chain.actions[0] = STRATEGY_PASS;
			cleared++;
		}
		i++;
	}
	return (cleared);
}
