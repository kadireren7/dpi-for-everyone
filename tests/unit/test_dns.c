#include "dns.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---- canned-response builder ---- */

typedef struct s_rr
{
	uint16_t	type;
	uint32_t	ttl;
	uint8_t		data[16];
	uint16_t	len;
}	t_rr;

static void	w16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* Echoes `query`'s header+question back as a response with `rcode`
 * and the given answer records (each owner name = pointer to the
 * question name at offset 12). */
static size_t	build_reply(const uint8_t *query, size_t qlen, int rcode,
	const t_rr *rrs, size_t rr_count, uint8_t *out)
{
	size_t	pos;
	size_t	i;

	memcpy(out, query, qlen);
	out[2] = 0x81;
	out[3] = (uint8_t)(0x80 | rcode);
	w16(out + 6, (uint16_t)rr_count);
	pos = qlen;
	i = 0;
	while (i < rr_count)
	{
		out[pos++] = 0xC0;
		out[pos++] = 12;
		w16(out + pos, rrs[i].type);
		w16(out + pos + 2, 1);
		out[pos + 4] = (uint8_t)(rrs[i].ttl >> 24);
		out[pos + 5] = (uint8_t)(rrs[i].ttl >> 16);
		out[pos + 6] = (uint8_t)(rrs[i].ttl >> 8);
		out[pos + 7] = (uint8_t)rrs[i].ttl;
		w16(out + pos + 8, rrs[i].len);
		pos += 10;
		memcpy(out + pos, rrs[i].data, rrs[i].len);
		pos += rrs[i].len;
		i++;
	}
	return (pos);
}

static t_rr	a_rr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint32_t ttl)
{
	t_rr	rr;

	memset(&rr, 0, sizeof(rr));
	rr.type = DNS_QTYPE_A;
	rr.ttl = ttl;
	rr.len = 4;
	rr.data[0] = a;
	rr.data[1] = b;
	rr.data[2] = c;
	rr.data[3] = d;
	return (rr);
}

/* ---- scripted mock transport ---- */

typedef enum e_behavior
{
	B_ANSWER,	/* reply with the configured records */
	B_TIMEOUT,
	B_SERVFAIL,
	B_NXDOMAIN,
	B_WRONG_ID,
	B_LOCAL_ERR
}	t_behavior;

typedef struct s_mock
{
	t_behavior	behavior[DNS_MAX_SERVERS];
	t_rr		rrs[DNS_MAX_SERVERS][4];
	size_t		rr_count[DNS_MAX_SERVERS];
	int			calls[DNS_MAX_SERVERS];
	int			total_calls;
}	t_mock;

static long	mock_transport(size_t idx, const uint8_t *query, size_t qlen,
	uint8_t *reply, size_t reply_size, int timeout_ms, void *userdata)
{
	t_mock	*m;
	size_t	n;

	(void)reply_size;
	(void)timeout_ms;
	m = userdata;
	m->calls[idx]++;
	m->total_calls++;
	if (m->behavior[idx] == B_TIMEOUT)
		return (0);
	if (m->behavior[idx] == B_LOCAL_ERR)
		return (-1);
	if (m->behavior[idx] == B_SERVFAIL)
		return ((long)build_reply(query, qlen, 2, NULL, 0, reply));
	if (m->behavior[idx] == B_NXDOMAIN)
		return ((long)build_reply(query, qlen, 3, NULL, 0, reply));
	n = build_reply(query, qlen, 0, m->rrs[idx], m->rr_count[idx], reply);
	if (m->behavior[idx] == B_WRONG_ID)
		reply[1] ^= 0xFF;
	return ((long)n);
}

/* ---- tests ---- */

static void	test_query_encoding(void)
{
	uint8_t	q[512];
	size_t	len;

	len = dns_build_query(0x1234, "discord.com", DNS_QTYPE_A, q, sizeof(q));
	assert(len == 12 + 13 + 4);
	assert(q[0] == 0x12 && q[1] == 0x34);
	assert(q[2] == 0x01);
	assert(q[12] == 7 && memcmp(q + 13, "discord", 7) == 0);
	assert(q[20] == 3 && memcmp(q + 21, "com", 3) == 0);
	assert(q[24] == 0);
	assert(dns_build_query(1, "discord.com.", DNS_QTYPE_A, q, sizeof(q))
		== len);
	assert(dns_build_query(1, "", DNS_QTYPE_A, q, sizeof(q)) == 0);
	assert(dns_build_query(1, "a..b", DNS_QTYPE_A, q, sizeof(q)) == 0);
	assert(dns_build_query(1, "x"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
			DNS_QTYPE_A, q, sizeof(q)) == 0);
}

static void	test_multiple_a_records_and_min_ttl(void)
{
	uint8_t			q[512];
	uint8_t			r[1500];
	size_t			qlen;
	size_t			rlen;
	t_rr			rrs[3];
	t_dns_answer	ans;

	qlen = dns_build_query(7, "discord.com", DNS_QTYPE_A, q, sizeof(q));
	rrs[0] = a_rr(162, 159, 137, 232, 300);
	rrs[1] = a_rr(162, 159, 138, 232, 120);
	rrs[2] = a_rr(162, 159, 128, 233, 600);
	rlen = build_reply(q, qlen, 0, rrs, 3, r);
	assert(dns_parse_response(r, rlen, 7, "DISCORD.com", DNS_QTYPE_A, &ans)
		== DNS_OK);
	assert(ans.count == 3);
	assert(ans.addrs[0].family == 4);
	assert(ans.addrs[1].addr[0] == 162 && ans.addrs[1].addr[2] == 138);
	assert(ans.ttl == 120);
}

static void	test_aaaa_and_cname_chain(void)
{
	uint8_t			q[512];
	uint8_t			r[1500];
	size_t			qlen;
	size_t			rlen;
	t_rr			rrs[2];
	t_dns_answer	ans;

	qlen = dns_build_query(9, "gateway.discord.gg", DNS_QTYPE_AAAA, q,
			sizeof(q));
	memset(rrs, 0, sizeof(rrs));
	/* a CNAME-typed record first (rdata content irrelevant, skipped) */
	rrs[0].type = 5;
	rrs[0].ttl = 50;
	rrs[0].len = 2;
	rrs[0].data[0] = 0xC0;
	rrs[0].data[1] = 12;
	rrs[1].type = DNS_QTYPE_AAAA;
	rrs[1].ttl = 200;
	rrs[1].len = 16;
	rrs[1].data[0] = 0x26;
	rrs[1].data[1] = 0x06;
	rrs[1].data[15] = 0x01;
	rlen = build_reply(q, qlen, 0, rrs, 2, r);
	assert(dns_parse_response(r, rlen, 9, "gateway.discord.gg",
			DNS_QTYPE_AAAA, &ans) == DNS_OK);
	assert(ans.count == 1);
	assert(ans.addrs[0].family == 6);
	assert(ans.addrs[0].addr[0] == 0x26 && ans.addrs[0].addr[15] == 0x01);
	/* the CNAME's TTL doesn't count, only used address records */
	assert(ans.ttl == 200);
}

static void	test_reply_must_match_query(void)
{
	uint8_t			q[512];
	uint8_t			r[1500];
	size_t			qlen;
	size_t			rlen;
	t_rr			rr;
	t_dns_answer	ans;

	rr = a_rr(1, 2, 3, 4, 60);
	qlen = dns_build_query(42, "discord.com", DNS_QTYPE_A, q, sizeof(q));
	rlen = build_reply(q, qlen, 0, &rr, 1, r);
	assert(dns_parse_response(r, rlen, 43, "discord.com", DNS_QTYPE_A,
			&ans) == DNS_ERR_MALFORMED);
	assert(dns_parse_response(r, rlen, 42, "discord.gg", DNS_QTYPE_A,
			&ans) == DNS_ERR_MALFORMED);
	assert(dns_parse_response(r, rlen, 42, "discord.com", DNS_QTYPE_AAAA,
			&ans) == DNS_ERR_MALFORMED);
	assert(dns_parse_response(r, rlen - 2, 42, "discord.com", DNS_QTYPE_A,
			&ans) == DNS_ERR_MALFORMED);
	assert(dns_parse_response(q, qlen, 42, "discord.com", DNS_QTYPE_A,
			&ans) == DNS_ERR_MALFORMED);
	r[2] |= 0x02; /* TC: truncated over UDP, don't trust a partial list */
	assert(dns_parse_response(r, rlen, 42, "discord.com", DNS_QTYPE_A,
			&ans) == DNS_ERR_MALFORMED);
}

/* The observed failure: the router answers discord.com with the ISP's
 * block host. The trusted resolver never asks the router, so the
 * answer comes from the configured servers only. */
static void	test_trusted_answer_not_poisoned_one(void)
{
	t_dns_resolver	*r;
	static t_dns_resolver	resolver;
	t_mock			m;
	t_dns_answer	ans;

	r = &resolver;
	memset(&m, 0, sizeof(m));
	m.behavior[0] = B_ANSWER;
	m.rrs[0][0] = a_rr(162, 159, 137, 232, 300);
	m.rr_count[0] = 1;
	dns_resolver_init(r, 1, mock_transport, &m, 1000, 1);
	assert(dns_resolve(r, "discord.com", DNS_QTYPE_A, 1000, &ans) == DNS_OK);
	assert(ans.count == 1);
	assert(!(ans.addrs[0].addr[0] == 195 && ans.addrs[0].addr[1] == 175));
	assert(ans.addrs[0].addr[0] == 162);
}

static void	test_fallback_order_on_timeout_servfail_and_spoof(void)
{
	static t_dns_resolver	r;
	t_mock					m;
	t_dns_answer			ans;

	memset(&m, 0, sizeof(m));
	m.behavior[0] = B_TIMEOUT;
	m.behavior[1] = B_SERVFAIL;
	m.behavior[2] = B_WRONG_ID;
	m.behavior[3] = B_LOCAL_ERR;
	m.behavior[4] = B_ANSWER;
	m.rrs[4][0] = a_rr(162, 159, 128, 233, 300);
	m.rr_count[4] = 1;
	dns_resolver_init(&r, 5, mock_transport, &m, 1000, 1);
	assert(dns_resolve(&r, "discord.com", DNS_QTYPE_A, 1000, &ans) == DNS_OK);
	assert(ans.addrs[0].addr[2] == 128);
	assert(m.calls[0] == 1 && m.calls[1] == 1 && m.calls[2] == 1
		&& m.calls[3] == 1 && m.calls[4] == 1);
	assert(r.health[0].consecutive_failures == 1);
	assert(r.health[4].consecutive_failures == 0);
}

static void	test_nxdomain_is_authoritative(void)
{
	static t_dns_resolver	r;
	t_mock					m;
	t_dns_answer			ans;

	memset(&m, 0, sizeof(m));
	m.behavior[0] = B_NXDOMAIN;
	m.behavior[1] = B_ANSWER;
	dns_resolver_init(&r, 2, mock_transport, &m, 1000, 1);
	assert(dns_resolve(&r, "nope.invalid", DNS_QTYPE_A, 1000, &ans)
		== DNS_NXDOMAIN);
	assert(m.calls[1] == 0);
	/* negative answers are cached briefly too */
	assert(dns_resolve(&r, "nope.invalid", DNS_QTYPE_A, 1010, &ans)
		== DNS_NXDOMAIN);
	assert(m.total_calls == 1);
	assert(dns_resolve(&r, "nope.invalid", DNS_QTYPE_A,
			1000 + DNS_NEGATIVE_TTL + 1, &ans) == DNS_NXDOMAIN);
	assert(m.total_calls == 2);
}

static void	test_all_servers_fail(void)
{
	static t_dns_resolver	r;
	t_mock					m;
	t_dns_answer			ans;

	memset(&m, 0, sizeof(m));
	m.behavior[0] = B_TIMEOUT;
	m.behavior[1] = B_TIMEOUT;
	dns_resolver_init(&r, 2, mock_transport, &m, 1000, 1);
	assert(dns_resolve(&r, "discord.com", DNS_QTYPE_A, 1000, &ans)
		== DNS_ERR_ALL_FAILED);
	assert(ans.count == 0);
	/* failures are not cached: the next call asks again */
	assert(dns_resolve(&r, "discord.com", DNS_QTYPE_A, 1001, &ans)
		== DNS_ERR_ALL_FAILED);
	assert(m.total_calls == 4);
}

static void	test_cache_hit_and_ttl_expiry_with_clamps(void)
{
	static t_dns_resolver	r;
	t_mock					m;
	t_dns_answer			ans;

	memset(&m, 0, sizeof(m));
	m.behavior[0] = B_ANSWER;
	m.rrs[0][0] = a_rr(162, 159, 137, 232, 100);
	m.rr_count[0] = 1;
	dns_resolver_init(&r, 1, mock_transport, &m, 1000, 1);
	assert(dns_resolve(&r, "discord.com", DNS_QTYPE_A, 1000, &ans) == DNS_OK);
	assert(dns_resolve(&r, "Discord.COM", DNS_QTYPE_A, 1099, &ans) == DNS_OK);
	assert(m.total_calls == 1 && r.cache_hits == 1);
	/* A and AAAA are cached separately */
	m.rr_count[0] = 0;
	assert(dns_resolve(&r, "discord.com", DNS_QTYPE_AAAA, 1099, &ans)
		== DNS_NODATA);
	assert(m.total_calls == 2);
	m.rr_count[0] = 1;
	assert(dns_resolve(&r, "discord.com", DNS_QTYPE_A, 1100, &ans) == DNS_OK);
	assert(m.total_calls == 3);

	/* TTL 0 is clamped up to DNS_TTL_MIN, huge TTLs down to DNS_TTL_MAX */
	m.rrs[0][0] = a_rr(1, 1, 1, 1, 0);
	assert(dns_resolve(&r, "zero.example", DNS_QTYPE_A, 2000, &ans) == DNS_OK);
	assert(dns_resolve(&r, "zero.example", DNS_QTYPE_A,
			2000 + DNS_TTL_MIN - 1, &ans) == DNS_OK);
	assert(m.total_calls == 4);
	m.rrs[0][0] = a_rr(1, 1, 1, 1, 86400 * 7);
	assert(dns_resolve(&r, "long.example", DNS_QTYPE_A, 3000, &ans) == DNS_OK);
	assert(dns_resolve(&r, "long.example", DNS_QTYPE_A,
			3000 + DNS_TTL_MAX + 1, &ans) == DNS_OK);
	assert(m.total_calls == 6);

	dns_cache_flush(&r);
	assert(dns_resolve(&r, "discord.com", DNS_QTYPE_A, 1101, &ans) == DNS_OK);
	assert(m.total_calls == 7);
}

static void	test_server_backoff_and_health(void)
{
	static t_dns_resolver	r;
	t_mock					m;
	t_dns_answer			ans;
	int						i;

	memset(&m, 0, sizeof(m));
	m.behavior[0] = B_TIMEOUT;
	m.behavior[1] = B_ANSWER;
	m.rrs[1][0] = a_rr(9, 9, 9, 9, 30);
	m.rr_count[1] = 1;
	dns_resolver_init(&r, 2, mock_transport, &m, 1000, 1);
	i = 0;
	while (i < DNS_SERVER_FAIL_LIMIT)
	{
		dns_cache_flush(&r);
		assert(dns_resolve(&r, "a.example", DNS_QTYPE_A, 100, &ans) == DNS_OK);
		i++;
	}
	assert(r.health[0].skip_until == 100 + DNS_SERVER_BACKOFF_SECONDS);
	/* backed off: server 0 is not asked first any more */
	dns_cache_flush(&r);
	assert(dns_resolve(&r, "a.example", DNS_QTYPE_A, 101, &ans) == DNS_OK);
	assert(m.calls[0] == DNS_SERVER_FAIL_LIMIT);
	assert(dns_resolver_healthy(&r, 101));
	/* everything backed off: still tried (last resort), not skipped */
	m.behavior[1] = B_TIMEOUT;
	i = 0;
	while (i < DNS_SERVER_FAIL_LIMIT)
	{
		dns_cache_flush(&r);
		dns_resolve(&r, "a.example", DNS_QTYPE_A, 102, &ans);
		i++;
	}
	assert(!dns_resolver_healthy(&r, 103));
	m.behavior[0] = B_ANSWER;
	m.rrs[0][0] = a_rr(8, 8, 8, 8, 30);
	m.rr_count[0] = 1;
	dns_cache_flush(&r);
	assert(dns_resolve(&r, "a.example", DNS_QTYPE_A, 103, &ans) == DNS_OK);
	assert(r.health[0].consecutive_failures == 0);
	assert(dns_resolver_healthy(&r, 103));
}

static void	test_udp_server_list_parse(void)
{
	t_dns_udp_servers	s;

	assert(dns_udp_servers_parse(&s, DNS_DEFAULT_SERVERS, 0) == 5);
	assert(dns_udp_servers_parse(&s,
			"1.1.1.1, bogus ,2606:4700:4700::1111,,999.1.1.1", 0x1234) == 2);
	assert(s.so_mark == 0x1234);
	assert(dns_udp_servers_parse(&s, "", 0) == 0);
}

/* ---- raw forwarding ---- */

static void	test_forwarding(void)
{
	t_dns_resolver	r;
	t_mock			m;
	uint8_t			q[512];
	uint8_t			reply[1500];
	char			name[DNS_NAME_MAX];
	uint16_t		qtype;
	uint16_t		udp_size;
	size_t			qlen;
	long			n;

	/* plain query: no EDNS -> 512 */
	qlen = dns_build_query(0x4242, "Gateway.Discord.GG", DNS_QTYPE_AAAA, q,
			sizeof(q));
	assert(dns_query_info(q, qlen, name, sizeof(name), &qtype, &udp_size)
		== 0);
	assert(strcmp(name, "gateway.discord.gg") == 0);
	assert(qtype == DNS_QTYPE_AAAA && udp_size == 512);
	/* with an OPT record advertising 1232 bytes */
	memcpy(q + qlen, "\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00", 11);
	q[11] = 1;
	assert(dns_query_info(q, qlen + 11, name, sizeof(name), &qtype,
			&udp_size) == 0 && udp_size == 1232);
	/* a response is not a query */
	q[2] |= 0x80;
	assert(dns_query_info(q, qlen, name, sizeof(name), &qtype, &udp_size)
		== -1);
	/* exchange: SERVFAIL and a wrong id are skipped, the next server's
	 * answer to this exact query is returned byte for byte */
	qlen = dns_build_query(0x7777, "discord.com", DNS_QTYPE_A, q, sizeof(q));
	memset(&m, 0, sizeof(m));
	m.behavior[0] = B_SERVFAIL;
	m.behavior[1] = B_WRONG_ID;
	m.behavior[2] = B_ANSWER;
	m.rrs[2][0] = a_rr(162, 159, 128, 233, 300);
	m.rr_count[2] = 1;
	dns_resolver_init(&r, 3, mock_transport, &m, 100, 1);
	n = dns_exchange(&r, q, qlen, reply, sizeof(reply), 100);
	assert(n == (long)qlen + 16);
	assert(reply[0] == 0x77 && reply[1] == 0x77 && (reply[2] & 0x80));
	assert(memcmp(reply + n - 4, "\xa2\x9f\x80\xe9", 4) == 0);
	assert(r.health[0].consecutive_failures == 1);
	assert(r.health[2].consecutive_failures == 0);
	/* everyone fails: -1 (the forwarder answers SERVFAIL) */
	m.behavior[2] = B_TIMEOUT;
	assert(dns_exchange(&r, q, qlen, reply, sizeof(reply), 100) == -1);
	n = (long)dns_servfail_reply(q, qlen, reply, sizeof(reply));
	assert(n == (long)qlen && (reply[2] & 0x80) && (reply[3] & 0x0F) == 2);
	assert(reply[0] == 0x77 && !(reply[2] & 0x02));
	n = (long)dns_truncated_reply(q, qlen, reply, sizeof(reply));
	assert(n == (long)qlen && (reply[2] & 0x02) && (reply[3] & 0x0F) == 0);
	assert(reply[6] == 0 && reply[7] == 0 && reply[11] == 0);
	assert(dns_truncated_reply(q, 5, reply, sizeof(reply)) == 0);
}

int	main(void)
{
	test_query_encoding();
	test_forwarding();
	test_multiple_a_records_and_min_ttl();
	test_aaaa_and_cname_chain();
	test_reply_must_match_query();
	test_trusted_answer_not_poisoned_one();
	test_fallback_order_on_timeout_servfail_and_spoof();
	test_nxdomain_is_authoritative();
	test_all_servers_fail();
	test_cache_hit_and_ttl_expiry_with_clamps();
	test_server_backoff_and_health();
	test_udp_server_list_parse();
	printf("test_dns: OK\n");
	return (0);
}
