#include "tp.h"
#include "netfingerprint.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FP 0x1111222233334444ULL
#define FP_OTHER 0x5555666677778888ULL
#define NOW 1700000000

static t_tp_step	step(t_tp_target t, t_strategy s)
{
	t_tp_step	r;

	r.target = t;
	r.strategy = s;
	return (r);
}

static void	expect_attempt(const t_tp_plan *p, t_tp_target t, t_strategy s)
{
	t_tp_step	got;
	int			timeout;

	assert(tp_plan_next(p, &got, &timeout) == TP_NEXT_ATTEMPT);
	assert(got.target == t);
	assert(got.strategy == s);
	assert(timeout > 0);
}

static void	expect(const t_tp_plan *p, t_tp_next want)
{
	t_tp_step	got;
	int			timeout;

	assert(tp_plan_next(p, &got, &timeout) == want);
}

/* ---- plan ---- */

static void	test_no_host_is_single_direct(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_RESET);
	expect(&p, TP_NEXT_DONE);
	assert(tp_plan_source(&p) == TP_SRC_NONE);
}

/* 1-2: DIRECT first; success ends the plan, with no DNS lookup at all
 * (DNS disagreement can't even be observed for working traffic). */
static void	test_direct_success_needs_no_dns(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS), TP_RES_OK);
	expect(&p, TP_NEXT_DONE);
	assert(p.trust == TP_TRUST_UNKNOWN);
	assert(tp_plan_source(&p) == TP_SRC_LADDER);
}

/* A TLS alert is the real server's answer: relayed, not retried. */
static void	test_alert_is_final(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_ALERT);
	expect(&p, TP_NEXT_DONE);
}

/* 3-4, 7: DIRECT fails -> trusted DNS; same address -> TLSREC there. */
static void	test_direct_fails_dns_agrees(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_RESET);
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MATCH;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC),
		TP_RES_TIMEOUT);
	/* then the other record-split variant (extra TCP cut) */
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC_SPLIT);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC_SPLIT),
		TP_RES_TIMEOUT);
	expect(&p, TP_NEXT_DONE);
}

/* 5, 7: DIRECT fails, trusted DNS disagrees -> trusted DIRECT, then
 * trusted TLSREC; never more than TP_MAX_ATTEMPTS. */
static void	test_direct_fails_dns_disagrees(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_TIMEOUT);
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MISMATCH;
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_TRUSTED, STRATEGY_PASS), TP_RES_RESET);
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_TLSREC);
	tp_plan_record(&p, step(TP_TARGET_TRUSTED, STRATEGY_TLSREC),
		TP_RES_RESET);
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_TLSREC_SPLIT);
	tp_plan_record(&p, step(TP_TARGET_TRUSTED, STRATEGY_TLSREC_SPLIT),
		TP_RES_RESET);
	expect(&p, TP_NEXT_DONE);
	assert(p.ntried == TP_MAX_ATTEMPTS);
}

/* A known-blocked host: bypass first (no DIRECT probe that would only
 * time out against the DPI), both variants, then the ordinary ladder
 * as a last resort. */
static void	test_listed_bypasses_first(void)
{
	t_tp_plan	p;

	assert(tp_host_listed("discord.com"));
	assert(tp_host_listed("gateway.discord.gg"));
	assert(tp_host_listed("CDN.DISCORDAPP.COM."));
	assert(!tp_host_listed("notdiscord.com"));
	assert(!tp_host_listed("discord.com.evil.example"));
	assert(!tp_host_listed("example.com"));
	assert(!tp_host_listed(NULL));
	tp_plan_init(&p);
	p.has_host = 1;
	p.listed = 1;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC),
		TP_RES_RESET);
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC_SPLIT);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC_SPLIT),
		TP_RES_RESET);
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_RESET);
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MISMATCH;
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_TRUSTED, STRATEGY_PASS),
		TP_RES_RESET);
	expect(&p, TP_NEXT_DONE);
	/* the network's last working variant leads */
	tp_plan_init(&p);
	p.has_host = 1;
	p.listed = 1;
	p.preferred = STRATEGY_TLSREC_SPLIT;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC_SPLIT);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC_SPLIT),
		TP_RES_OK);
	expect(&p, TP_NEXT_DONE);
	/* unreachable address: no second rewrite against it */
	tp_plan_init(&p);
	p.has_host = 1;
	p.listed = 1;
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC),
		TP_RES_CONNECT_FAIL);
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MATCH;
	expect(&p, TP_NEXT_DONE);
	/* in cooldown a listed host still gets its one bypass attempt */
	tp_plan_init(&p);
	p.has_host = 1;
	p.listed = 1;
	p.in_cooldown = 1;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC),
		TP_RES_RESET);
	expect(&p, TP_NEXT_DONE);
	assert(tp_plan_source(&p) == TP_SRC_COOLDOWN);
}

/* Trusted resolver has nothing: stay on the original address. */
static void	test_dns_none_stays_original(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_RESET);
	p.trust = TP_TRUST_NONE;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
}

/* A refused/unreachable destination the resolvers agree on is an
 * ordinary failure: no strategy is tried against it. */
static void	test_connect_fail_is_not_interference(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_CONNECT_FAIL);
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MATCH;
	expect(&p, TP_NEXT_DONE);
	/* ...but a poisoned answer can point at a dead address */
	p.trust = TP_TRUST_MISMATCH;
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_PASS);
}

/* The poisoned-DNS case: DIRECT was verified bad, so it is skipped
 * and the lookup happens up front. */
static void	test_direct_bad_skips_direct(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	p.direct_bad = 1;
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MISMATCH;
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_TRUSTED, STRATEGY_PASS), TP_RES_RESET);
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_TLSREC);
	/* same with agreeing DNS: straight to TLSREC on the original */
	tp_plan_init(&p);
	p.has_host = 1;
	p.direct_bad = 1;
	p.trust = TP_TRUST_MATCH;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
}

static void	test_cached_decision_first(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	p.has_cached = 1;
	p.cached = step(TP_TARGET_TRUSTED, STRATEGY_TLSREC);
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MISMATCH;
	expect_attempt(&p, TP_TARGET_TRUSTED, STRATEGY_TLSREC);
	assert(tp_plan_source(&p) == TP_SRC_CACHED);
	/* the cached step stopped working: back to the ladder, bounded */
	tp_plan_record(&p, step(TP_TARGET_TRUSTED, STRATEGY_TLSREC),
		TP_RES_RESET);
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS), TP_RES_OK);
	expect(&p, TP_NEXT_DONE);
	assert(tp_plan_source(&p) == TP_SRC_LADDER);
}

/* A cached "trusted" decision whose resolvers now agree (the network's
 * DNS got fixed) just means the original address. */
static void	test_cached_trusted_normalizes(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	p.has_cached = 1;
	p.cached = step(TP_TARGET_TRUSTED, STRATEGY_TLSREC);
	p.trust = TP_TRUST_MATCH;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
}

static void	test_manual_overrides(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	p.has_manual = 1;
	p.manual = STRATEGY_TLSREC;
	p.has_cached = 1;
	p.cached = step(TP_TARGET_ORIGINAL, STRATEGY_PASS);
	expect(&p, TP_NEXT_NEED_DNS);
	p.trust = TP_TRUST_MATCH;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC),
		TP_RES_RESET);
	expect(&p, TP_NEXT_DONE);
	assert(tp_plan_source(&p) == TP_SRC_MANUAL);
	/* packet-mode names in a manual rule run as the stream strategy */
	tp_plan_init(&p);
	p.has_host = 1;
	p.has_manual = 1;
	p.manual = STRATEGY_SPLIT;
	p.trust = TP_TRUST_MATCH;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
	/* manual pass: direct only, no DNS */
	tp_plan_init(&p);
	p.has_host = 1;
	p.has_manual = 1;
	p.manual = STRATEGY_PASS;
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_RESET);
	expect(&p, TP_NEXT_DONE);
}

static void	test_cooldown_is_direct_once(void)
{
	t_tp_plan	p;

	tp_plan_init(&p);
	p.has_host = 1;
	p.in_cooldown = 1;
	p.has_cached = 1;
	p.cached = step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC);
	expect_attempt(&p, TP_TARGET_ORIGINAL, STRATEGY_PASS);
	tp_plan_record(&p, step(TP_TARGET_ORIGINAL, STRATEGY_PASS),
		TP_RES_TIMEOUT);
	expect(&p, TP_NEXT_DONE);
	assert(tp_plan_source(&p) == TP_SRC_COOLDOWN);
}

/* ---- decisions ---- */

static void	test_direct_never_stored(void)
{
	t_tp_decisions	d;

	tp_decisions_init(&d);
	tp_decision_success(&d, "example.com", FP, 4, NOW,
		step(TP_TARGET_ORIGINAL, STRATEGY_PASS));
	assert(d.count == 0);
	assert(!d.dirty);
	tp_decisions_free(&d);
}

/* 6, 9: stored per exact host, network, family, with expiry. */
static void	test_decision_scope_and_expiry(void)
{
	t_tp_decisions	d;
	t_tp_decision	*e;

	tp_decisions_init(&d);
	tp_decision_success(&d, "discord.com", FP, 4, NOW,
		step(TP_TARGET_TRUSTED, STRATEGY_TLSREC));
	assert(d.dirty);
	e = tp_decision_lookup(&d, "DISCORD.com", FP, 4, NOW + 10);
	assert(e != NULL && e->step.target == TP_TARGET_TRUSTED
		&& e->step.strategy == STRATEGY_TLSREC);
	assert(tp_decision_lookup(&d, "discord.com", FP, 6, NOW) == NULL);
	assert(tp_decision_lookup(&d, "discord.com", FP_OTHER, 4, NOW) == NULL);
	/* 10: no inheritance to siblings or parents */
	assert(tp_decision_lookup(&d, "cdn.discord.com", FP, 4, NOW) == NULL);
	assert(tp_decision_lookup(&d, "com", FP, 4, NOW) == NULL);
	assert(tp_decision_lookup(&d, "discord.com", FP, 4,
			NOW + TP_DECISION_TTL_SECONDS) == NULL);
	/* nothing is ever learned on an unknown network */
	tp_decision_success(&d, "x.example", NETFP_UNKNOWN, 4, NOW,
		step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
	assert(d.count == 1);
	assert(tp_decision_lookup(&d, "x.example", NETFP_UNKNOWN, 4, NOW)
		== NULL);
	tp_decisions_free(&d);
}

/* "A destination that works directly stays DIRECT": a later direct
 * success drops the decision. */
static void	test_direct_success_drops_decision(void)
{
	t_tp_decisions	d;

	tp_decisions_init(&d);
	tp_decision_success(&d, "a.example", FP, 4, NOW,
		step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
	d.dirty = 0;
	tp_decision_success(&d, "a.example", FP, 4, NOW + 5,
		step(TP_TARGET_ORIGINAL, STRATEGY_PASS));
	assert(tp_decision_lookup(&d, "a.example", FP, 4, NOW + 5) == NULL);
	assert(d.dirty);
	tp_decisions_free(&d);
}

/* Steady traffic doesn't rewrite the file every connection. */
static void	test_refresh_is_throttled(void)
{
	t_tp_decisions	d;

	tp_decisions_init(&d);
	tp_decision_success(&d, "a.example", FP, 4, NOW,
		step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
	d.dirty = 0;
	tp_decision_success(&d, "a.example", FP, 4, NOW + 60,
		step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
	assert(!d.dirty);
	tp_decision_success(&d, "a.example", FP, 4,
		NOW + TP_DECISION_TTL_SECONDS / 2 + 1,
		step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
	assert(d.dirty);
	tp_decisions_free(&d);
}

static void	test_failure_cooldown(void)
{
	t_tp_decisions	d;

	tp_decisions_init(&d);
	tp_decision_success(&d, "b.example", FP, 4, NOW,
		step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
	tp_decision_failure(&d, "b.example", FP, 4, NOW);
	assert(tp_decision_lookup(&d, "b.example", FP, 4, NOW) == NULL);
	assert(tp_in_cooldown(&d, "b.example", NOW + 1));
	assert(!tp_in_cooldown(&d, "b.example", NOW + TP_COOLDOWN_SECONDS));
	assert(!tp_in_cooldown(&d, "c.example", NOW));
	tp_decision_failure(&d, "b.example", FP, 4, NOW);
	tp_decision_success(&d, "b.example", FP, 4, NOW + 2,
		step(TP_TARGET_ORIGINAL, STRATEGY_PASS));
	assert(!tp_in_cooldown(&d, "b.example", NOW + 3));
	tp_decisions_free(&d);
}

static void	test_direct_bad_marks(void)
{
	t_tp_decisions	d;

	tp_decisions_init(&d);
	tp_direct_bad_mark(&d, "discord.com", FP, 4, NOW);
	assert(tp_direct_bad(&d, "discord.com", FP, 4, NOW + 1));
	assert(!tp_direct_bad(&d, "discord.com", FP, 6, NOW + 1));
	assert(!tp_direct_bad(&d, "discord.com", FP_OTHER, 4, NOW + 1));
	assert(!tp_direct_bad(&d, "gateway.discord.gg", FP, 4, NOW + 1));
	assert(!tp_direct_bad(&d, "discord.com", FP, 4,
			NOW + TP_DIRECT_BAD_TTL_SECONDS));
	tp_direct_bad_mark(&d, "x.example", NETFP_UNKNOWN, 4, NOW);
	assert(!tp_direct_bad(&d, "x.example", NETFP_UNKNOWN, 4, NOW));
	/* a network change forgets marks and cooldowns, keeps decisions */
	tp_decision_success(&d, "keep.example", FP, 4, NOW,
		step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
	tp_decision_failure(&d, "cool.example", FP, 4, NOW);
	tp_decisions_network_changed(&d);
	assert(!tp_direct_bad(&d, "discord.com", FP, 4, NOW + 1));
	assert(!tp_in_cooldown(&d, "cool.example", NOW + 1));
	assert(tp_decision_lookup(&d, "keep.example", FP, 4, NOW) != NULL);
	tp_decisions_free(&d);
}

static void	test_persistence_roundtrip(void)
{
	t_tp_decisions	d;
	t_tp_decisions	back;
	char			buf[4096];
	size_t			len;
	t_tp_decision	*e;
	const char		*bad = "# comment\n\n"
		"garbage line\n"
		"a.example 0 4 tlsrec original 1\n"			/* unknown network */
		"b.example 1 5 tlsrec original 1\n"			/* bad family */
		"c.example 1 4 split original 1\n"			/* not a stream step */
		"d.example 1 4 pass original 1\n"			/* direct: never stored */
		"e.example 1 4 tlsrec sideways 1\n";

	tp_decisions_init(&d);
	tp_decision_success(&d, "discord.com", FP, 4, NOW,
		step(TP_TARGET_TRUSTED, STRATEGY_TLSREC));
	tp_decision_success(&d, "v6.example", FP_OTHER, 6, NOW,
		step(TP_TARGET_TRUSTED, STRATEGY_PASS));
	len = tp_decisions_serialize(&d, buf, sizeof(buf));
	assert(len > 0);
	assert(tp_decisions_serialize(&d, buf, 20) == 0);
	tp_decisions_init(&back);
	assert(tp_decisions_parse(&back, buf, len) == 0);
	assert(back.count == 2 && !back.dirty);
	e = tp_decision_lookup(&back, "discord.com", FP, 4, NOW);
	assert(e != NULL && e->step.target == TP_TARGET_TRUSTED
		&& e->step.strategy == STRATEGY_TLSREC && e->validated_at == NOW);
	e = tp_decision_lookup(&back, "v6.example", FP_OTHER, 6, NOW);
	assert(e != NULL && e->step.strategy == STRATEGY_PASS);
	tp_decisions_free(&back);
	tp_decisions_init(&back);
	assert(tp_decisions_parse(&back, bad, strlen(bad)) == 6);
	assert(back.count == 0);
	tp_decisions_free(&back);
	tp_decisions_free(&d);
}

/* Grows on demand, bounded; the oldest is evicted when full. */
static void	test_bounded_growth(void)
{
	t_tp_decisions	d;
	char			host[64];
	size_t			i;

	tp_decisions_init(&d);
	assert(d.cap == 0 && d.entries == NULL);
	i = 0;
	while (i < TP_DECISIONS_MAX + 10)
	{
		snprintf(host, sizeof(host), "h%zu.example", i);
		tp_decision_success(&d, host, FP, 4, NOW + (int64_t)i,
			step(TP_TARGET_ORIGINAL, STRATEGY_TLSREC));
		i++;
	}
	assert(d.count == TP_DECISIONS_MAX && d.cap == TP_DECISIONS_MAX);
	assert(tp_decision_lookup(&d, "h0.example", FP, 4, NOW + 20000) == NULL);
	snprintf(host, sizeof(host), "h%d.example", TP_DECISIONS_MAX + 9);
	assert(tp_decision_lookup(&d, host, FP, 4, NOW + 20000) != NULL);
	tp_decisions_free(&d);
}

/* ---- nftables text ---- */

static void	test_nft_ruleset(void)
{
	char	buf[4096];
	size_t	len;

	len = tp_nft_ruleset(buf, sizeof(buf), 1091, 1, 0);
	assert(len > 0 && len == strlen(buf));
	assert(strstr(buf, "dport @alive_dns") == NULL);
	/* idempotent: replaces only our own table, in one transaction */
	assert(strstr(buf, "table inet dpi_proxy_tp {}\n"
			"delete table inet dpi_proxy_tp\n") == buf);
	assert(strstr(buf, "table inet dpi_proxy {") == NULL);
	/* loop prevention and exclusions come before the redirect */
	/* ours (TP_SOCKET_MARK) and any other component's marked sockets:
	 * regression for a live loop with another transparent proxy that
	 * exempted only its own mark */
	assert(strstr(buf, "meta mark != 0 return") < strstr(buf, "redirect"));
	assert(strstr(strstr(buf, "output_filter"), "meta mark != 0 return")
		< strstr(buf, "quic_block4 counter reject"));
	assert(strstr(buf, "oifname \"lo\" return") < strstr(buf, "redirect"));
	assert(strstr(buf, "127.0.0.0/8") != NULL);
	assert(strstr(buf, "192.168.0.0/16") != NULL);
	assert(strstr(buf, "fe80::/10") != NULL);
	/* fail-open: only ports in the heartbeat set are redirected */
	assert(strstr(buf, "tcp dport @alive counter redirect to :1091") != NULL);
	assert(strstr(buf, "set alive { type inet_service; flags timeout; }"));
	assert(strstr(buf, "meta nfproto ipv6 return") == NULL);
	/* QUIC is rejected only to listed destinations */
	assert(strstr(buf, "udp dport 443 ip daddr @quic_block4 counter reject"));
	assert(strstr(buf, "udp dport 443 reject") == NULL);
	assert(tp_nft_ruleset(buf, 100, 1091, 1, 0) == 0);
	len = tp_nft_ruleset(buf, sizeof(buf), 1091, 0, 0);
	assert(strstr(buf, "meta nfproto ipv6 return") < strstr(buf, "redirect"));
	/* DNS interception: after the mark and loopback exemptions (our own
	 * resolver sockets; the app -> local stub hop), before the private
	 * returns (the router's resolver is the poisoned one), gated */
	len = tp_nft_ruleset(buf, sizeof(buf), 1091, 1, 1053);
	assert(len > 0);
	assert(strstr(buf, "set alive_dns { type inet_service; flags timeout; }"));
	assert(strstr(buf, "udp dport @alive_dns counter redirect to :1053"));
	assert(strstr(buf, "tcp dport @alive_dns counter redirect to :1053"));
	assert(strstr(buf, "meta mark != 0 return")
		< strstr(buf, "udp dport @alive_dns"));
	assert(strstr(buf, "oifname \"lo\" return")
		< strstr(buf, "udp dport @alive_dns"));
	assert(strstr(buf, "tcp dport @alive_dns") < strstr(buf, "192.168.0.0/16"));
	assert(strstr(buf, "tcp dport @alive counter redirect to :1091") != NULL);
	len = tp_nft_heartbeat(buf, sizeof(buf), 0);
	assert(len > 0);
	assert(strstr(buf, "flush set inet dpi_proxy_tp alive\n"
			"add element inet dpi_proxy_tp alive { 443 timeout 30s }\n"));
	assert(strstr(buf, "flush set inet dpi_proxy_tp alive_dns\n"));
	assert(strstr(buf, "alive_dns { 53") == NULL);
	len = tp_nft_heartbeat(buf, sizeof(buf), 1);
	assert(strstr(buf, "add element inet dpi_proxy_tp alive_dns "
			"{ 53 timeout 30s }\n"));
	len = tp_nft_quic_block(buf, sizeof(buf), 4, "162.159.128.233");
	assert(len > 0);
	assert(strstr(buf, "quic_block4 { 162.159.128.233 timeout 3600s }"));
	len = tp_nft_quic_block(buf, sizeof(buf), 6, "2606:4700::1");
	assert(strstr(buf, "quic_block6 { 2606:4700::1 timeout 3600s }"));
}

/* ---- PF anchor text (macOS) ---- */

static void	test_pf_ruleset(void)
{
	char	buf[8192];
	size_t	len;

	len = tp_pf_ruleset(buf, sizeof(buf), 1091, 0, 0);
	assert(len > 0 && len == strlen(buf));
	/* tables, translation, filtering — in the order pfctl requires */
	assert(strstr(buf, "table <dpi_local4> const") < strstr(buf, "rdr pass"));
	assert(strstr(buf, "rdr pass") < strstr(buf, "block return"));
	assert(strstr(buf, "block return") < strstr(buf, "pass out quick"));
	assert(strstr(buf, "rdr pass on lo0 inet proto tcp from any port "
			"40000 <> 48999 to ! <dpi_local4> port 443 -> 127.0.0.1 port "
			"1091\n") != NULL);
	assert(strstr(buf, "pass out quick on ! lo0 route-to (lo0 127.0.0.1) "
			"inet proto tcp from any port 40000 <> 48999 to ! <dpi_local4> "
			"port 443 flags S/SA keep state\n") != NULL);
	assert(strstr(buf, "block return out quick inet proto udp from any to "
			"<dpi_quic4> port 443\n") != NULL);
	/* private and loopback destinations are never redirected */
	assert(strstr(buf, "192.168.0.0/16") != NULL);
	assert(strstr(buf, "127.0.0.0/8") != NULL);
	/* no IPv6 listener, no DNS forwarder: neither is touched */
	assert(strstr(buf, "inet6 proto tcp") == NULL);
	assert(strstr(buf, "port 53") == NULL);
	len = tp_pf_ruleset(buf, sizeof(buf), 1091, 1, 1053);
	assert(len > 0);
	assert(strstr(buf, "rdr pass on lo0 inet6 proto tcp from any port 40000 "
			"<> 48999 to ! <dpi_local6> port 443 -> ::1 port 1091\n") != NULL);
	assert(strstr(buf, "route-to (lo0 ::1) inet6 proto tcp") != NULL);
	assert(strstr(buf, "rdr pass on lo0 inet proto { udp, tcp } from any port "
			"40000 <> 48999 to ! 127.0.0.0/8 port 53 -> 127.0.0.1 port 1053\n")
		!= NULL);
	assert(strstr(buf, "route-to (lo0 127.0.0.1) inet proto udp from any "
			"port 40000 <> 48999 to ! 127.0.0.0/8 port 53 keep state\n")
		!= NULL);
	/* the router's DNS (private) is intercepted: only loopback and
	 * IPv6 link-local/multicast servers are excluded */
	assert(strstr(buf, "to ! <dpi_local4> port 53") == NULL);
	assert(strstr(buf, "table <dpi_nodns6> const { ::1/128, fe80::/10, "
			"ff00::/8 }") != NULL);
	/* every interception rule skips our own source ports */
	assert(strstr(buf, "pass out quick on ! lo0 route-to") != NULL);
	{
		const char	*p;
		size_t		rules;

		rules = 0;
		p = buf;
		while ((p = strstr(p, "route-to")) != NULL)
		{
			rules++;
			p++;
		}
		assert(rules == 6);
		rules = 0;
		p = buf;
		while ((p = strstr(p, "port 40000 <> 48999")) != NULL)
		{
			rules++;
			p++;
		}
		assert(rules == 10);
	}
	/* too small: nothing half-written is returned */
	assert(tp_pf_ruleset(buf, 200, 1091, 1, 1053) == 0);
	assert(tp_pf_ruleset(buf, 0, 1091, 1, 1053) == 0);
	assert(tp_pf_ruleset(buf, len, 1091, 1, 1053) == 0);
	assert(tp_pf_ruleset(buf, len + 1, 1091, 1, 1053) == len);
}

int	main(void)
{
	test_no_host_is_single_direct();
	test_direct_success_needs_no_dns();
	test_alert_is_final();
	test_direct_fails_dns_agrees();
	test_direct_fails_dns_disagrees();
	test_listed_bypasses_first();
	test_dns_none_stays_original();
	test_connect_fail_is_not_interference();
	test_direct_bad_skips_direct();
	test_cached_decision_first();
	test_cached_trusted_normalizes();
	test_manual_overrides();
	test_cooldown_is_direct_once();
	test_direct_never_stored();
	test_decision_scope_and_expiry();
	test_direct_success_drops_decision();
	test_refresh_is_throttled();
	test_failure_cooldown();
	test_direct_bad_marks();
	test_persistence_roundtrip();
	test_bounded_growth();
	test_nft_ruleset();
	test_pf_ruleset();
	printf("test_transparent: OK\n");
	return (0);
}
