#include "dns.h"

#include <ctype.h>
#include <string.h>

const char	*dns_status_name(t_dns_status s)
{
	if (s == DNS_OK)
		return ("ok");
	if (s == DNS_NODATA)
		return ("nodata");
	if (s == DNS_NXDOMAIN)
		return ("nxdomain");
	if (s == DNS_ERR_TIMEOUT)
		return ("timeout");
	if (s == DNS_ERR_MALFORMED)
		return ("malformed");
	if (s == DNS_ERR_SERVFAIL)
		return ("servfail");
	return ("all_failed");
}

static uint16_t	rd16(const uint8_t *p)
{
	return ((uint16_t)((p[0] << 8) | p[1]));
}

static uint32_t	rd32(const uint8_t *p)
{
	return (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
		| ((uint32_t)p[2] << 8) | p[3]);
}

static void	wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* Encodes `name` as length-prefixed labels (a trailing dot is
 * accepted). Returns bytes written, 0 on an invalid name. */
static size_t	encode_name(const char *name, uint8_t *out, size_t out_size)
{
	size_t	pos;
	size_t	label_start;
	size_t	i;
	size_t	len;

	len = strlen(name);
	if (len > 0 && name[len - 1] == '.')
		len--;
	if (len == 0 || len > 253 || len + 2 > out_size)
		return (0);
	pos = 0;
	i = 0;
	while (i < len)
	{
		label_start = i;
		while (i < len && name[i] != '.')
			i++;
		if (i - label_start == 0 || i - label_start > 63)
			return (0);
		out[pos++] = (uint8_t)(i - label_start);
		memcpy(out + pos, name + label_start, i - label_start);
		pos += i - label_start;
		i++;
	}
	out[pos++] = 0;
	return (pos);
}

size_t	dns_build_query(uint16_t id, const char *name, uint16_t qtype,
	uint8_t *out, size_t out_size)
{
	size_t	name_len;

	if (out_size < 12 + 4)
		return (0);
	memset(out, 0, 12);
	wr16(out, id);
	out[2] = 0x01;
	wr16(out + 4, 1);
	name_len = encode_name(name, out + 12, out_size - 12 - 4);
	if (name_len == 0)
		return (0);
	wr16(out + 12 + name_len, qtype);
	wr16(out + 12 + name_len + 2, 1);
	return (12 + name_len + 4);
}

/* Skips a (possibly compressed) name starting at *pos. */
static int	skip_name(const uint8_t *pkt, size_t len, size_t *pos)
{
	size_t	guard;

	guard = 0;
	while (*pos < len && guard++ < 128)
	{
		if (pkt[*pos] == 0)
		{
			(*pos)++;
			return (0);
		}
		if ((pkt[*pos] & 0xC0) == 0xC0)
		{
			if (*pos + 2 > len)
				return (-1);
			*pos += 2;
			return (0);
		}
		if ((pkt[*pos] & 0xC0) != 0)
			return (-1);
		*pos += 1 + pkt[*pos];
	}
	return (-1);
}

/* Case-insensitively compares the uncompressed question name at `pos`
 * against the encoding of `name`. */
static int	question_matches(const uint8_t *pkt, size_t len, size_t pos,
	const char *name, uint16_t qtype, size_t *after)
{
	uint8_t	enc[DNS_NAME_MAX + 2];
	size_t	enc_len;
	size_t	i;

	enc_len = encode_name(name, enc, sizeof(enc));
	if (enc_len == 0 || pos + enc_len + 4 > len)
		return (0);
	i = 0;
	while (i < enc_len)
	{
		if (tolower(pkt[pos + i]) != tolower(enc[i]))
			return (0);
		i++;
	}
	if (rd16(pkt + pos + enc_len) != qtype
		|| rd16(pkt + pos + enc_len + 2) != 1)
		return (0);
	*after = pos + enc_len + 4;
	return (1);
}

t_dns_status	dns_parse_response(const uint8_t *pkt, size_t len,
	uint16_t id, const char *name, uint16_t qtype, t_dns_answer *out)
{
	size_t		pos;
	uint16_t	ancount;
	uint16_t	rtype;
	uint16_t	rdlen;
	uint32_t	ttl;
	int			rcode;

	out->count = 0;
	out->ttl = DNS_TTL_MAX;
	if (len < 12 || rd16(pkt) != id || !(pkt[2] & 0x80)
		|| (pkt[2] & 0x02) || rd16(pkt + 4) != 1)
		return (DNS_ERR_MALFORMED);
	if (!question_matches(pkt, len, 12, name, qtype, &pos))
		return (DNS_ERR_MALFORMED);
	rcode = pkt[3] & 0x0F;
	if (rcode == 3)
		return (DNS_NXDOMAIN);
	if (rcode != 0)
		return (DNS_ERR_SERVFAIL);
	ancount = rd16(pkt + 6);
	while (ancount-- > 0)
	{
		if (skip_name(pkt, len, &pos) < 0 || pos + 10 > len)
			return (DNS_ERR_MALFORMED);
		rtype = rd16(pkt + pos);
		ttl = rd32(pkt + pos + 4);
		rdlen = rd16(pkt + pos + 8);
		pos += 10;
		if (pos + rdlen > len)
			return (DNS_ERR_MALFORMED);
		if (rtype == qtype && out->count < DNS_MAX_ADDRS
			&& ((qtype == DNS_QTYPE_A && rdlen == 4)
				|| (qtype == DNS_QTYPE_AAAA && rdlen == 16)))
		{
			memset(&out->addrs[out->count], 0, sizeof(out->addrs[0]));
			out->addrs[out->count].family = (qtype == DNS_QTYPE_A) ? 4 : 6;
			memcpy(out->addrs[out->count].addr, pkt + pos, rdlen);
			out->count++;
			if (ttl < out->ttl)
				out->ttl = ttl;
		}
		pos += rdlen;
	}
	if (out->count == 0)
		return (DNS_NODATA);
	return (DNS_OK);
}

void	dns_resolver_init(t_dns_resolver *r, size_t server_count,
	t_dns_transport transport, void *transport_data, int timeout_ms,
	uint16_t id_seed)
{
	memset(r, 0, sizeof(*r));
	if (server_count > DNS_MAX_SERVERS)
		server_count = DNS_MAX_SERVERS;
	r->server_count = server_count;
	r->transport = transport;
	r->transport_data = transport_data;
	r->timeout_ms = timeout_ms;
	r->next_id = id_seed;
}

void	dns_cache_flush(t_dns_resolver *r)
{
	memset(r->cache, 0, sizeof(r->cache));
}

int	dns_resolver_healthy(const t_dns_resolver *r, int64_t now)
{
	size_t	i;

	i = 0;
	while (i < r->server_count)
	{
		if (r->health[i].skip_until <= now)
			return (1);
		i++;
	}
	return (0);
}

static int	name_ieq(const char *a, const char *b)
{
	while (*a && *b)
	{
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return (0);
		a++;
		b++;
	}
	return (*a == *b);
}

static t_dns_cache_entry	*cache_find(t_dns_resolver *r, const char *name,
	uint16_t qtype)
{
	size_t	i;

	i = 0;
	while (i < DNS_CACHE_SIZE)
	{
		if (r->cache[i].name[0] != '\0' && r->cache[i].qtype == qtype
			&& name_ieq(r->cache[i].name, name))
			return (&r->cache[i]);
		i++;
	}
	return (NULL);
}

/* Reuses the entry for name+qtype, else an empty/expired slot, else
 * the least recently used one — bounded, never grows. */
static void	cache_store(t_dns_resolver *r, const char *name, uint16_t qtype,
	t_dns_status status, const t_dns_answer *answer, int64_t now)
{
	t_dns_cache_entry	*slot;
	uint32_t			ttl;
	size_t				i;

	if (strlen(name) >= DNS_NAME_MAX)
		return ;
	slot = cache_find(r, name, qtype);
	i = 0;
	while (slot == NULL && i < DNS_CACHE_SIZE)
	{
		if (r->cache[i].name[0] == '\0' || r->cache[i].expires_at <= now)
			slot = &r->cache[i];
		i++;
	}
	if (slot == NULL)
	{
		slot = &r->cache[0];
		i = 1;
		while (i < DNS_CACHE_SIZE)
		{
			if (r->cache[i].last_used < slot->last_used)
				slot = &r->cache[i];
			i++;
		}
	}
	ttl = (status == DNS_OK) ? answer->ttl : DNS_NEGATIVE_TTL;
	if (ttl < DNS_TTL_MIN)
		ttl = DNS_TTL_MIN;
	if (ttl > DNS_TTL_MAX)
		ttl = DNS_TTL_MAX;
	strcpy(slot->name, name);
	slot->qtype = qtype;
	slot->status = status;
	slot->answer = *answer;
	slot->answer.ttl = ttl;
	slot->expires_at = now + ttl;
	slot->last_used = now;
}

static void	server_result(t_dns_resolver *r, size_t idx, int ok, int64_t now)
{
	r->health[idx].queries++;
	if (ok)
	{
		r->health[idx].consecutive_failures = 0;
		r->health[idx].skip_until = 0;
		return ;
	}
	r->health[idx].failures++;
	r->health[idx].consecutive_failures++;
	if (r->health[idx].consecutive_failures >= DNS_SERVER_FAIL_LIMIT)
		r->health[idx].skip_until = now + DNS_SERVER_BACKOFF_SECONDS;
}

static void	lock(t_dns_resolver *r, int on)
{
	if (r->lock != NULL)
		r->lock(r->lock_ctx, on);
}

static t_dns_status	query_server(t_dns_resolver *r, size_t idx,
	uint16_t id, const char *name, uint16_t qtype, t_dns_answer *out)
{
	uint8_t		query[512];
	uint8_t		reply[1500];
	size_t		qlen;
	long		n;

	qlen = dns_build_query(id, name, qtype, query, sizeof(query));
	if (qlen == 0)
		return (DNS_ERR_MALFORMED);
	n = r->transport(idx, query, qlen, reply, sizeof(reply), r->timeout_ms,
			r->transport_data);
	if (n == 0)
		return (DNS_ERR_TIMEOUT);
	if (n < 0)
		return (DNS_ERR_SERVFAIL);
	return (dns_parse_response(reply, (size_t)n, id, name, qtype, out));
}

t_dns_status	dns_resolve(t_dns_resolver *r, const char *name,
	uint16_t qtype, int64_t now, t_dns_answer *out)
{
	t_dns_cache_entry	*hit;
	t_dns_status		st;
	size_t				order[DNS_MAX_SERVERS];
	size_t				n;
	size_t				pass;
	size_t				i;
	uint16_t			id;

	lock(r, 1);
	hit = cache_find(r, name, qtype);
	if (hit != NULL && hit->expires_at > now)
	{
		r->cache_hits++;
		hit->last_used = now;
		*out = hit->answer;
		st = hit->status;
		lock(r, 0);
		return (st);
	}
	r->cache_misses++;
	/* healthy servers in list order, then backed-off ones */
	n = 0;
	pass = 0;
	while (pass < 2)
	{
		i = 0;
		while (i < r->server_count)
		{
			if ((r->health[i].skip_until > now) == (int)pass)
				order[n++] = i;
			i++;
		}
		pass++;
	}
	id = r->next_id;
	r->next_id = (uint16_t)(r->next_id + r->server_count);
	lock(r, 0);
	i = 0;
	while (i < n)
	{
		st = query_server(r, order[i], (uint16_t)(id + i), name, qtype, out);
		lock(r, 1);
		server_result(r, order[i], st == DNS_OK || st == DNS_NODATA
			|| st == DNS_NXDOMAIN, now);
		if (st == DNS_OK || st == DNS_NODATA || st == DNS_NXDOMAIN)
		{
			cache_store(r, name, qtype, st, out, now);
			lock(r, 0);
			return (st);
		}
		lock(r, 0);
		i++;
	}
	out->count = 0;
	return (DNS_ERR_ALL_FAILED);
}

/* ---- raw forwarding (the local DNS forwarder) ---- */

int	dns_query_info(const uint8_t *pkt, size_t len, char *name,
	size_t name_size, uint16_t *qtype, uint16_t *udp_size)
{
	size_t	pos;
	size_t	n;
	size_t	lab;

	if (len < 12 || (pkt[2] & 0x80) || (pkt[2] & 0x78) != 0
		|| rd16(pkt + 4) != 1 || name_size < 2)
		return (-1);
	pos = 12;
	n = 0;
	while (pos < len && pkt[pos] != 0)
	{
		lab = pkt[pos];
		if ((lab & 0xC0) != 0 || pos + 1 + lab > len
			|| n + lab + 2 > name_size)
			return (-1);
		if (n > 0)
			name[n++] = '.';
		memcpy(name + n, pkt + pos + 1, lab);
		while (lab-- > 0)
		{
			name[n] = (char)tolower((unsigned char)name[n]);
			n++;
		}
		pos += 1 + pkt[pos];
	}
	if (pos + 5 > len)
		return (-1);
	name[n] = '\0';
	*qtype = rd16(pkt + pos + 1);
	pos += 5;
	*udp_size = 512;
	/* a plain query has no answer/authority records; its additional
	 * section may start with the EDNS OPT record (root name, type 41,
	 * class = the client's UDP payload size) */
	if (rd16(pkt + 6) == 0 && rd16(pkt + 8) == 0 && rd16(pkt + 10) >= 1
		&& pos + 11 <= len && pkt[pos] == 0 && rd16(pkt + pos + 1) == 41
		&& rd16(pkt + pos + 3) > 512)
		*udp_size = rd16(pkt + pos + 3);
	return (0);
}

/* Length of the question section (one uncompressed question). */
static size_t	question_len(const uint8_t *pkt, size_t len)
{
	size_t	pos;

	pos = 12;
	while (pos < len && pkt[pos] != 0)
	{
		if ((pkt[pos] & 0xC0) != 0)
			return (0);
		pos += 1 + pkt[pos];
	}
	if (pos + 5 > len)
		return (0);
	return (pos + 5 - 12);
}

/* Does `reply` answer exactly `query` (id, QR, same question)? */
static int	reply_matches(const uint8_t *query, size_t qlen,
	const uint8_t *reply, size_t rlen)
{
	size_t	ql;
	size_t	i;

	ql = question_len(query, qlen);
	if (ql == 0 || rlen < 12 + ql || rd16(reply) != rd16(query)
		|| !(reply[2] & 0x80) || rd16(reply + 4) != 1)
		return (0);
	i = 0;
	while (i < ql)
	{
		if (tolower(reply[12 + i]) != tolower(query[12 + i]))
			return (0);
		i++;
	}
	return (1);
}

long	dns_exchange(t_dns_resolver *r, const uint8_t *query, size_t qlen,
	uint8_t *reply, size_t reply_size, int64_t now)
{
	size_t	order[DNS_MAX_SERVERS];
	size_t	n;
	size_t	pass;
	size_t	i;
	long	got;
	int		rcode;
	int		ok;

	if (qlen < 12 || question_len(query, qlen) == 0)
		return (-1);
	lock(r, 1);
	n = 0;
	pass = 0;
	while (pass < 2)
	{
		i = 0;
		while (i < r->server_count)
		{
			if ((r->health[i].skip_until > now) == (int)pass)
				order[n++] = i;
			i++;
		}
		pass++;
	}
	lock(r, 0);
	i = 0;
	while (i < n)
	{
		got = r->transport(order[i], query, qlen, reply, reply_size,
				r->timeout_ms, r->transport_data);
		ok = (got > 0 && reply_matches(query, qlen, reply, (size_t)got));
		rcode = ok ? (reply[3] & 0x0F) : -1;
		/* SERVFAIL / REFUSED: that server's problem, ask the next */
		if (rcode == 2 || rcode == 5)
			ok = 0;
		lock(r, 1);
		server_result(r, order[i], ok, now);
		lock(r, 0);
		if (ok)
			return (got);
		i++;
	}
	return (-1);
}

size_t	dns_truncated_reply(const uint8_t *query, size_t qlen, uint8_t *out,
	size_t out_size)
{
	size_t	ql;

	ql = question_len(query, qlen);
	if (ql == 0 || out_size < 12 + ql)
		return (0);
	memcpy(out, query, 12 + ql);
	out[2] = (uint8_t)((query[2] & 0x79) | 0x80 | 0x02);
	out[3] = 0x80;
	wr16(out + 6, 0);
	wr16(out + 8, 0);
	wr16(out + 10, 0);
	return (12 + ql);
}

size_t	dns_servfail_reply(const uint8_t *query, size_t qlen, uint8_t *out,
	size_t out_size)
{
	size_t	n;

	n = dns_truncated_reply(query, qlen, out, out_size);
	if (n == 0)
		return (0);
	out[2] = (uint8_t)(out[2] & ~0x02);
	out[3] = 0x80 | 0x02;
	return (n);
}
