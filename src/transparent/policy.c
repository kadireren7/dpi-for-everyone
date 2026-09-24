#include "tp.h"
#include "netfingerprint.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

const char	*tp_target_name(t_tp_target t)
{
	if (t == TP_TARGET_TRUSTED)
		return ("trusted");
	return ("original");
}

const char	*tp_result_name(t_tp_result r)
{
	static const char	*names[] = {"ok", "alert", "connect-fail", "reset",
		"closed", "timeout", "not-tls", "skipped"};

	if ((size_t)r < sizeof(names) / sizeof(names[0]))
		return (names[r]);
	return ("?");
}

const char	*tp_source_name(t_tp_source s)
{
	if (s == TP_SRC_MANUAL)
		return ("manual");
	if (s == TP_SRC_CACHED)
		return ("cached");
	if (s == TP_SRC_LADDER)
		return ("auto");
	if (s == TP_SRC_COOLDOWN)
		return ("cooldown");
	return ("none");
}

/* ---- known-blocked hosts ---- */

static const char	*g_listed[] = {
	"discord.com", "discordapp.com", "discordapp.net", "discord.gg",
	"discord.media", "discord.dev", "discord.new", "discord.gift",
	"discordstatus.com", "discordcdn.com", "dis.gd",
	"roblox.com", "rbxcdn.com", "wattpad.com",
	"instagram.com", "cdninstagram.com",
	"rutracker.org", "nyaa.si", "1337x.to", "thepiratebay.org",
	NULL
};

int	tp_host_listed(const char *host)
{
	size_t	hlen;
	size_t	dlen;
	size_t	i;

	if (host == NULL)
		return (0);
	hlen = strlen(host);
	while (hlen > 0 && host[hlen - 1] == '.')
		hlen--;
	i = 0;
	while (g_listed[i] != NULL)
	{
		dlen = strlen(g_listed[i]);
		if (hlen == dlen && strncasecmp(host, g_listed[i], dlen) == 0)
			return (1);
		if (hlen > dlen && host[hlen - dlen - 1] == '.'
			&& strncasecmp(host + hlen - dlen, g_listed[i], dlen) == 0)
			return (1);
		i++;
	}
	return (0);
}

/* ---- attempt planning ---- */

void	tp_plan_init(t_tp_plan *p)
{
	memset(p, 0, sizeof(*p));
}

static t_tp_step	step_of(t_tp_target target, t_strategy strategy)
{
	t_tp_step	s;

	s.target = target;
	s.strategy = strategy;
	return (s);
}

/* Only PASS, TLSREC and TLSREC_SPLIT mean anything in this mode; a
 * packet-mode strategy in a manual rule (split, fake, ...) runs as
 * TLSREC, the one manipulation a stream proxy has. */
static t_strategy	stream_strategy(t_strategy s)
{
	if (s == STRATEGY_PASS || s == STRATEGY_TLSREC_SPLIT)
		return (s);
	return (STRATEGY_TLSREC);
}

/* The bypass tried first (the network's last working one, else
 * TLSREC) and the other variant after it. */
static t_strategy	first_bypass(const t_tp_plan *p)
{
	if (p->preferred == STRATEGY_TLSREC_SPLIT)
		return (STRATEGY_TLSREC_SPLIT);
	return (STRATEGY_TLSREC);
}

static t_strategy	second_bypass(const t_tp_plan *p)
{
	if (first_bypass(p) == STRATEGY_TLSREC)
		return (STRATEGY_TLSREC_SPLIT);
	return (STRATEGY_TLSREC);
}

/* The trusted address is only worth using when the resolvers
 * disagree; otherwise it's the same destination. */
static t_tp_step	normalize(const t_tp_plan *p, t_tp_step s)
{
	if (s.target == TP_TARGET_TRUSTED && p->trust != TP_TRUST_MISMATCH)
		s.target = TP_TARGET_ORIGINAL;
	s.strategy = stream_strategy(s.strategy);
	return (s);
}

static int	was_tried(const t_tp_plan *p, t_tp_step s, t_tp_result *result)
{
	size_t	i;

	i = 0;
	while (i < p->ntried)
	{
		if (p->tried[i].target == s.target
			&& p->tried[i].strategy == s.strategy)
		{
			if (result != NULL)
				*result = p->results[i];
			return (1);
		}
		i++;
	}
	return (0);
}

static t_tp_next	offer(const t_tp_plan *p, t_tp_step s, t_tp_step *out,
	int *timeout_ms)
{
	(void)p;
	*out = s;
	*timeout_ms = TP_REPLY_TIMEOUT_MS;
	return (TP_NEXT_ATTEMPT);
}

/* Did any attempt to the application's own address fail to even
 * connect? Then no rewrite of the ClientHello can help there. */
static int	original_unreachable(const t_tp_plan *p)
{
	size_t	i;

	i = 0;
	while (i < p->ntried)
	{
		if (p->tried[i].target == TP_TARGET_ORIGINAL
			&& p->results[i] == TP_RES_CONNECT_FAIL)
			return (1);
		i++;
	}
	return (0);
}

/* Both bypass variants to `target`, in preference order, unless one
 * was already tried. */
static int	next_bypass(const t_tp_plan *p, t_tp_target target,
	t_tp_step *s)
{
	*s = step_of(target, first_bypass(p));
	if (!was_tried(p, *s, NULL))
		return (1);
	*s = step_of(target, second_bypass(p));
	return (!was_tried(p, *s, NULL));
}

t_tp_next	tp_plan_next(const t_tp_plan *p, t_tp_step *out, int *timeout_ms)
{
	t_tp_step	direct;
	t_tp_step	s;
	t_tp_result	direct_result;

	if (p->ntried >= TP_MAX_ATTEMPTS)
		return (TP_NEXT_DONE);
	if (p->ntried > 0 && (p->results[p->ntried - 1] == TP_RES_OK
			|| p->results[p->ntried - 1] == TP_RES_ALERT))
		return (TP_NEXT_DONE);
	direct = step_of(TP_TARGET_ORIGINAL, STRATEGY_PASS);
	if (!p->has_host
		|| (p->has_manual && stream_strategy(p->manual) == STRATEGY_PASS))
	{
		if (p->ntried == 0)
			return (offer(p, direct, out, timeout_ms));
		return (TP_NEXT_DONE);
	}
	/* cooldown: one attempt only — the way a listed (known blocked)
	 * host can work, the plain way for anything else */
	if (p->in_cooldown)
	{
		if (p->ntried > 0)
			return (TP_NEXT_DONE);
		if (p->listed)
			return (offer(p, step_of(TP_TARGET_ORIGINAL, first_bypass(p)),
					out, timeout_ms));
		return (offer(p, direct, out, timeout_ms));
	}
	if (p->has_manual)
	{
		if (p->ntried > 0)
			return (TP_NEXT_DONE);
		if (p->trust == TP_TRUST_UNKNOWN)
			return (TP_NEXT_NEED_DNS);
		return (offer(p, normalize(p,
					step_of(TP_TARGET_TRUSTED, p->manual)), out, timeout_ms));
	}
	if (p->has_cached)
	{
		if (p->cached.target == TP_TARGET_TRUSTED
			&& p->trust == TP_TRUST_UNKNOWN)
			return (TP_NEXT_NEED_DNS);
		s = normalize(p, p->cached);
		if (!was_tried(p, s, NULL))
			return (offer(p, s, out, timeout_ms));
	}
	/* A known blocked host: bypass straight away, no DIRECT probe
	 * that would only time out against the DPI first. */
	if (p->listed && !original_unreachable(p)
		&& next_bypass(p, TP_TARGET_ORIGINAL, &s))
		return (offer(p, s, out, timeout_ms));
	if (p->direct_bad)
		direct_result = TP_RES_SKIPPED;
	else if (original_unreachable(p) && !was_tried(p, direct, NULL))
		direct_result = TP_RES_CONNECT_FAIL;
	else if (!was_tried(p, direct, &direct_result))
		return (offer(p, direct, out, timeout_ms));
	/* DIRECT to the application's own address failed: now (and only
	 * now) is the trusted resolver's opinion worth a lookup. */
	if (p->trust == TP_TRUST_UNKNOWN)
		return (TP_NEXT_NEED_DNS);
	if (p->trust == TP_TRUST_MISMATCH)
	{
		s = step_of(TP_TARGET_TRUSTED, STRATEGY_PASS);
		if (!was_tried(p, s, NULL))
			return (offer(p, s, out, timeout_ms));
		if (next_bypass(p, TP_TARGET_TRUSTED, &s))
			return (offer(p, s, out, timeout_ms));
		return (TP_NEXT_DONE);
	}
	/* Same address either way, and it never even accepted the TCP
	 * connection: an ordinary destination failure, not something a
	 * ClientHello rewrite can fix. */
	if (direct_result == TP_RES_CONNECT_FAIL || original_unreachable(p))
		return (TP_NEXT_DONE);
	if (next_bypass(p, TP_TARGET_ORIGINAL, &s))
		return (offer(p, s, out, timeout_ms));
	return (TP_NEXT_DONE);
}

void	tp_plan_record(t_tp_plan *p, t_tp_step step, t_tp_result r)
{
	if (p->ntried >= TP_MAX_ATTEMPTS)
		return ;
	p->tried[p->ntried] = step;
	p->results[p->ntried] = r;
	p->ntried++;
}

t_tp_source	tp_plan_source(const t_tp_plan *p)
{
	if (!p->has_host)
		return (TP_SRC_NONE);
	if (p->has_manual)
		return (TP_SRC_MANUAL);
	if (p->in_cooldown)
		return (TP_SRC_COOLDOWN);
	if (p->has_cached && p->ntried <= 1)
		return (TP_SRC_CACHED);
	return (TP_SRC_LADDER);
}

/* ---- decisions ---- */

void	tp_decisions_init(t_tp_decisions *d)
{
	memset(d, 0, sizeof(*d));
}

void	tp_decisions_free(t_tp_decisions *d)
{
	free(d->entries);
	memset(d, 0, sizeof(*d));
}

static int	fresh(const t_tp_decision *e, uint64_t fp, int64_t now)
{
	return (fp != NETFP_UNKNOWN && e->fingerprint == fp
		&& now >= e->validated_at
		&& now - e->validated_at < TP_DECISION_TTL_SECONDS);
}

static t_tp_decision	*find(t_tp_decisions *d, const char *host,
	uint64_t fp, int family)
{
	size_t	i;

	i = 0;
	while (i < d->count)
	{
		if (d->entries[i].fingerprint == fp && d->entries[i].family == family
			&& strcasecmp(d->entries[i].host, host) == 0)
			return (&d->entries[i]);
		i++;
	}
	return (NULL);
}

t_tp_decision	*tp_decision_lookup(t_tp_decisions *d, const char *host,
	uint64_t fp, int family, int64_t now)
{
	t_tp_decision	*e;

	e = find(d, host, fp, family);
	if (e == NULL || !fresh(e, fp, now))
		return (NULL);
	return (e);
}

static void	remove_entry(t_tp_decisions *d, t_tp_decision *e)
{
	*e = d->entries[d->count - 1];
	d->count--;
	d->dirty = 1;
}

/* A slot for a new entry: grows the array geometrically up to
 * TP_DECISIONS_MAX, then evicts the least recently validated one. */
static t_tp_decision	*new_slot(t_tp_decisions *d)
{
	t_tp_decision	*grown;
	size_t			cap;
	size_t			i;
	size_t			oldest;

	if (d->count < d->cap)
		return (&d->entries[d->count++]);
	if (d->cap < TP_DECISIONS_MAX)
	{
		cap = d->cap ? d->cap * 2 : 16;
		if (cap > TP_DECISIONS_MAX)
			cap = TP_DECISIONS_MAX;
		grown = realloc(d->entries, cap * sizeof(*grown));
		if (grown != NULL)
		{
			d->entries = grown;
			d->cap = cap;
			return (&d->entries[d->count++]);
		}
		if (d->count == 0)
			return (NULL);
	}
	oldest = 0;
	i = 1;
	while (i < d->count)
	{
		if (d->entries[i].validated_at < d->entries[oldest].validated_at)
			oldest = i;
		i++;
	}
	return (&d->entries[oldest]);
}

static t_tp_cooldown	*cooldown_find(t_tp_decisions *d, const char *host)
{
	size_t	i;

	i = 0;
	while (i < TP_COOLDOWN_MAX)
	{
		if (d->cooldown[i].host[0] != '\0'
			&& strcasecmp(d->cooldown[i].host, host) == 0)
			return (&d->cooldown[i]);
		i++;
	}
	return (NULL);
}

void	tp_decision_success(t_tp_decisions *d, const char *host, uint64_t fp,
	int family, int64_t now, t_tp_step step)
{
	t_tp_cooldown	*cd;
	t_tp_decision	*e;

	cd = cooldown_find(d, host);
	if (cd != NULL)
		cd->host[0] = '\0';
	if (fp == NETFP_UNKNOWN || strlen(host) >= STRATEGY_DOMAIN_MAX)
		return ;
	e = find(d, host, fp, family);
	if (step.target == TP_TARGET_ORIGINAL && step.strategy == STRATEGY_PASS)
	{
		if (e != NULL)
			remove_entry(d, e);
		return ;
	}
	if (e != NULL && fresh(e, fp, now) && e->step.target == step.target
		&& e->step.strategy == step.strategy
		&& now - e->validated_at < TP_DECISION_TTL_SECONDS / 2)
		return ;
	if (e == NULL)
	{
		e = new_slot(d);
		if (e == NULL)
			return ;
		memset(e, 0, sizeof(*e));
		snprintf(e->host, sizeof(e->host), "%s", host);
		e->fingerprint = fp;
		e->family = family;
	}
	e->step = step;
	e->validated_at = now;
	d->dirty = 1;
}

void	tp_decision_failure(t_tp_decisions *d, const char *host, uint64_t fp,
	int family, int64_t now)
{
	t_tp_cooldown	*cd;
	t_tp_decision	*e;
	size_t			i;

	cd = cooldown_find(d, host);
	i = 0;
	while (cd == NULL && i < TP_COOLDOWN_MAX)
	{
		if (d->cooldown[i].host[0] == '\0' || d->cooldown[i].until <= now)
			cd = &d->cooldown[i];
		i++;
	}
	if (cd == NULL)
	{
		cd = &d->cooldown[0];
		i = 1;
		while (i < TP_COOLDOWN_MAX)
		{
			if (d->cooldown[i].until < cd->until)
				cd = &d->cooldown[i];
			i++;
		}
	}
	if (strlen(host) < sizeof(cd->host))
	{
		snprintf(cd->host, sizeof(cd->host), "%s", host);
		cd->until = now + TP_COOLDOWN_SECONDS;
	}
	e = find(d, host, fp, family);
	if (e != NULL)
		remove_entry(d, e);
}

int	tp_in_cooldown(const t_tp_decisions *d, const char *host, int64_t now)
{
	size_t	i;

	i = 0;
	while (i < TP_COOLDOWN_MAX)
	{
		if (d->cooldown[i].host[0] != '\0'
			&& strcasecmp(d->cooldown[i].host, host) == 0)
			return (d->cooldown[i].until > now);
		i++;
	}
	return (0);
}

static t_tp_mark	*mark_find(const t_tp_decisions *d, const char *host,
	uint64_t fp, int family)
{
	size_t	i;

	i = 0;
	while (i < TP_DIRECT_BAD_MAX)
	{
		if (d->direct_bad[i].host[0] != '\0'
			&& d->direct_bad[i].fingerprint == fp
			&& d->direct_bad[i].family == family
			&& strcasecmp(d->direct_bad[i].host, host) == 0)
			return ((t_tp_mark *)&d->direct_bad[i]);
		i++;
	}
	return (NULL);
}

void	tp_direct_bad_mark(t_tp_decisions *d, const char *host, uint64_t fp,
	int family, int64_t now)
{
	t_tp_mark	*m;
	size_t		i;

	if (fp == NETFP_UNKNOWN || strlen(host) >= STRATEGY_DOMAIN_MAX)
		return ;
	m = mark_find(d, host, fp, family);
	i = 0;
	while (m == NULL && i < TP_DIRECT_BAD_MAX)
	{
		if (d->direct_bad[i].host[0] == '\0' || d->direct_bad[i].until <= now)
			m = &d->direct_bad[i];
		i++;
	}
	if (m == NULL)
	{
		m = &d->direct_bad[0];
		i = 1;
		while (i < TP_DIRECT_BAD_MAX)
		{
			if (d->direct_bad[i].until < m->until)
				m = &d->direct_bad[i];
			i++;
		}
	}
	snprintf(m->host, sizeof(m->host), "%s", host);
	m->fingerprint = fp;
	m->family = family;
	m->until = now + TP_DIRECT_BAD_TTL_SECONDS;
}

int	tp_direct_bad(const t_tp_decisions *d, const char *host, uint64_t fp,
	int family, int64_t now)
{
	const t_tp_mark	*m;

	if (fp == NETFP_UNKNOWN)
		return (0);
	m = mark_find(d, host, fp, family);
	return (m != NULL && m->until > now);
}

void	tp_decisions_network_changed(t_tp_decisions *d)
{
	memset(d->cooldown, 0, sizeof(d->cooldown));
	memset(d->direct_bad, 0, sizeof(d->direct_bad));
}

static int	parse_line(t_tp_decisions *d, char *line)
{
	char			host[STRATEGY_DOMAIN_MAX];
	char			strat[32];
	char			target[32];
	unsigned long long	fp;
	long long		validated;
	int				family;
	t_tp_step		step;
	t_tp_decision	*e;

	if (sscanf(line, "%255s %llx %d %31s %31s %lld", host, &fp, &family,
			strat, target, &validated) != 6)
		return (-1);
	if ((family != 4 && family != 6) || fp == NETFP_UNKNOWN
		|| strategy_from_name(strat, &step.strategy) != 0
		|| (step.strategy != STRATEGY_PASS
			&& step.strategy != STRATEGY_TLSREC
			&& step.strategy != STRATEGY_TLSREC_SPLIT))
		return (-1);
	if (strcmp(target, "original") == 0)
		step.target = TP_TARGET_ORIGINAL;
	else if (strcmp(target, "trusted") == 0)
		step.target = TP_TARGET_TRUSTED;
	else
		return (-1);
	if (step.target == TP_TARGET_ORIGINAL && step.strategy == STRATEGY_PASS)
		return (-1);
	e = find(d, host, (uint64_t)fp, family);
	if (e == NULL)
	{
		e = new_slot(d);
		if (e == NULL)
			return (-1);
		memset(e, 0, sizeof(*e));
		snprintf(e->host, sizeof(e->host), "%s", host);
		e->fingerprint = (uint64_t)fp;
		e->family = family;
	}
	e->step = step;
	e->validated_at = (int64_t)validated;
	return (0);
}

size_t	tp_decisions_parse(t_tp_decisions *d, const char *text, size_t len)
{
	char	line[512];
	size_t	pos;
	size_t	n;
	size_t	skipped;
	size_t	i;

	pos = 0;
	skipped = 0;
	while (pos < len)
	{
		n = 0;
		while (pos < len && text[pos] != '\n')
		{
			if (n + 1 < sizeof(line))
				line[n++] = text[pos];
			pos++;
		}
		pos++;
		line[n] = '\0';
		i = 0;
		while (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')
			i++;
		if (line[i] == '\0' || line[i] == '#')
			continue ;
		if (parse_line(d, line + i) != 0)
			skipped++;
	}
	d->dirty = 0;
	return (skipped);
}

size_t	tp_decisions_serialize(const t_tp_decisions *d, char *out,
	size_t out_size)
{
	size_t	used;
	size_t	i;
	int		n;

	n = snprintf(out, out_size, "# dpi-proxyd decisions: host fingerprint "
			"family strategy target validated_at\n");
	if (n < 0 || (size_t)n >= out_size)
		return (0);
	used = (size_t)n;
	i = 0;
	while (i < d->count)
	{
		n = snprintf(out + used, out_size - used, "%s %016" PRIx64
				" %d %s %s %" PRId64 "\n", d->entries[i].host,
				d->entries[i].fingerprint, d->entries[i].family,
				strategy_name(d->entries[i].step.strategy),
				tp_target_name(d->entries[i].step.target),
				d->entries[i].validated_at);
		if (n < 0 || (size_t)n >= out_size - used)
			return (0);
		used += (size_t)n;
		i++;
	}
	return (used);
}

/* ---- nftables ---- */

size_t	tp_nft_ruleset(char *out, size_t out_size, int port, int ipv6,
	int dns_port)
{
	char	dns[256];
	int		n;

	/* DNS goes to our forwarder whatever server it was meant for —
	 * including a private one (the router, which is exactly the
	 * resolver that hands out block-page addresses) — so these rules
	 * come before the private-address returns. Loopback is left
	 * alone: the application -> local stub (systemd-resolved) hop
	 * stays as it is; the stub's own upstream queries are what get
	 * redirected. Gated by alive_dns like the TCP rule by alive. */
	dns[0] = '\0';
	if (dns_port > 0)
	{
		n = snprintf(dns, sizeof(dns),
				"\t\tudp dport @alive_dns counter redirect to :%d\n"
				"\t\ttcp dport @alive_dns counter redirect to :%d\n",
				dns_port, dns_port);
		if (n < 0 || (size_t)n >= sizeof(dns))
			return (0);
	}
	/* "table X {}" then "delete table X" first: creates-then-removes
	 * any previous copy of *our* table in the same atomic transaction,
	 * so (re)start is idempotent and a stale table from a crash is
	 * replaced, never duplicated — and nothing else is touched. */
	/* "meta mark != 0 return": our own sockets carry TP_SOCKET_MARK, and
	 * any socket some other component marked (a VPN's tunnel socket,
	 * another proxy's upstream) is that component's own traffic —
	 * intercepting it would loop the two through each other. */
	n = snprintf(out, out_size,
			"table inet %s {}\n"
			"delete table inet %s\n"
			"table inet %s {\n"
			"\tset alive { type inet_service; flags timeout; }\n"
			"\tset alive_dns { type inet_service; flags timeout; }\n"
			"\tset quic_block4 { type ipv4_addr; flags timeout; }\n"
			"\tset quic_block6 { type ipv6_addr; flags timeout; }\n"
			"\tchain output_nat {\n"
			"\t\ttype nat hook output priority -100; policy accept;\n"
			"\t\tmeta mark != 0 return\n"
			"\t\toifname \"lo\" return\n"
			"%s"
			"%s"
			"\t\tip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, "
			"127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, "
			"224.0.0.0/3 } return\n"
			"\t\tip6 daddr { ::1, fc00::/7, fe80::/10, ff00::/8 } return\n"
			"\t\ttcp dport @alive counter redirect to :%d\n"
			"\t}\n"
			"\tchain output_filter {\n"
			"\t\ttype filter hook output priority 0; policy accept;\n"
			"\t\tmeta mark != 0 return\n"
			"\t\tudp dport 443 ip daddr @quic_block4 counter reject\n"
			"\t\tudp dport 443 ip6 daddr @quic_block6 counter reject\n"
			"\t}\n"
			"}\n",
			TP_NFT_TABLE, TP_NFT_TABLE, TP_NFT_TABLE,
			ipv6 ? "" : "\t\tmeta nfproto ipv6 return\n", dns, port);
	if (n < 0 || (size_t)n >= out_size)
		return (0);
	return ((size_t)n);
}

size_t	tp_nft_heartbeat(char *out, size_t out_size, int dns)
{
	int	n;

	/* flush + add in one transaction: the element is replaced with a
	 * fresh timeout, with no instant where the set is empty */
	n = snprintf(out, out_size,
			"flush set inet %s alive\n"
			"add element inet %s alive { 443 timeout %ds }\n"
			"flush set inet %s alive_dns\n",
			TP_NFT_TABLE, TP_NFT_TABLE, TP_ALIVE_TIMEOUT_S, TP_NFT_TABLE);
	if (n < 0 || (size_t)n >= out_size)
		return (0);
	if (dns)
	{
		n += snprintf(out + n, out_size - (size_t)n,
				"add element inet %s alive_dns { 53 timeout %ds }\n",
				TP_NFT_TABLE, TP_ALIVE_TIMEOUT_S);
		if ((size_t)n >= out_size)
			return (0);
	}
	return ((size_t)n);
}

size_t	tp_nft_quic_block(char *out, size_t out_size, int family,
	const char *addr)
{
	const char	*set;
	int			n;

	set = (family == 6) ? "quic_block6" : "quic_block4";
	/* add (no-op if present), delete, add: refreshes the timeout */
	n = snprintf(out, out_size,
			"add element inet %s %s { %s timeout %ds }\n"
			"delete element inet %s %s { %s }\n"
			"add element inet %s %s { %s timeout %ds }\n",
			TP_NFT_TABLE, set, addr, TP_QUIC_BLOCK_TIMEOUT_S,
			TP_NFT_TABLE, set, addr,
			TP_NFT_TABLE, set, addr, TP_QUIC_BLOCK_TIMEOUT_S);
	if (n < 0 || (size_t)n >= out_size)
		return (0);
	return ((size_t)n);
}
