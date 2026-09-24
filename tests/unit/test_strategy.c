#include "strategy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void	test_default_is_pass(void)
{
	t_strategy_config	cfg;

	strategy_config_init(&cfg);
	assert(strategy_for_domain(&cfg, "anything.example") == STRATEGY_PASS);
}

static void	test_spec_example_config(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"default = pass\n"
		"\n"
		"[domains]\n"
		"example.com = pass\n"
		"discord.com = split\n";

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 0);
	assert(cfg.default_strategy == STRATEGY_PASS);
	assert(strategy_for_domain(&cfg, "example.com") == STRATEGY_PASS);
	assert(strategy_for_domain(&cfg, "discord.com") == STRATEGY_SPLIT);
	assert(strategy_for_domain(&cfg, "DISCORD.com") == STRATEGY_SPLIT);
	assert(strategy_for_domain(&cfg, "unlisted.example") == STRATEGY_PASS);
}

static void	test_malformed_lines_are_skipped_safely(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"default = pass\n"
		"this line has no equals sign\n"
		"default = not_a_real_strategy\n"
		"[domains]\n"
		"= missing_key\n"
		"discord.com =\n"
		"discord.com = teleport\n"
		"roblox.com = split\n";
	size_t				skipped;

	strategy_config_init(&cfg);
	skipped = strategy_config_parse(&cfg, text, strlen(text));

	assert(skipped == 5);
	assert(cfg.default_strategy == STRATEGY_PASS);
	assert(strategy_for_domain(&cfg, "discord.com") == STRATEGY_PASS);
	assert(strategy_for_domain(&cfg, "roblox.com") == STRATEGY_SPLIT);
}

static void	test_empty_config_stays_safe(void)
{
	t_strategy_config	cfg;

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, "", 0) == 0);
	assert(cfg.default_strategy == STRATEGY_PASS);
	assert(cfg.rule_count == 0);
}

static void	test_suffix_match(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"default = pass\n"
		"[domains]\n"
		".example.com = split\n"
		"discord.com = fake\n";

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 0);

	/* exact rule beats nothing, suffix rule matches the bare domain
	 * and any subdomain, and an unrelated domain that merely happens
	 * to end with the same letters must NOT match. */
	assert(strategy_for_domain(&cfg, "example.com") == STRATEGY_SPLIT);
	assert(strategy_for_domain(&cfg, "www.example.com") == STRATEGY_SPLIT);
	assert(strategy_for_domain(&cfg, "deep.sub.example.com")
		== STRATEGY_SPLIT);
	assert(strategy_for_domain(&cfg, "notexample.com") == STRATEGY_PASS);
	assert(strategy_for_domain(&cfg, "discord.com") == STRATEGY_FAKE);
}

static void	test_exact_rule_beats_suffix_rule(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"[domains]\n"
		".example.com = split\n"
		"www.example.com = pass\n";

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 0);
	assert(strategy_for_domain(&cfg, "www.example.com") == STRATEGY_PASS);
	assert(strategy_for_domain(&cfg, "other.example.com")
		== STRATEGY_SPLIT);
}

static void	test_duplicate_rule_last_write_wins(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"[domains]\n"
		"discord.com = pass\n"
		"discord.com = split\n"
		"DISCORD.COM = fake\n";

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 0);
	/* three lines for the same (case-insensitive) domain must collapse
	 * into exactly one rule, not three. */
	assert(cfg.rule_count == 1);
	assert(strategy_for_domain(&cfg, "discord.com") == STRATEGY_FAKE);
}

static void	test_comments_and_blank_lines_ignored(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"# this is a comment\n"
		"\n"
		"default = pass\n"
		"; also a comment\n"
		"\n"
		"[domains]\n"
		"# comment inside domains too\n"
		"discord.com = split\n";

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 0);
	assert(cfg.rule_count == 1);
	assert(strategy_for_domain(&cfg, "discord.com") == STRATEGY_SPLIT);
}

static void	test_unknown_section_is_skipped_safely(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"[bogus]\n"
		"discord.com = split\n"
		"[domains]\n"
		"roblox.com = split\n";
	size_t				skipped;

	strategy_config_init(&cfg);
	skipped = strategy_config_parse(&cfg, text, strlen(text));
	/* "discord.com = split" lands inside the unknown [bogus] section,
	 * not [domains], so it must not silently become a domain rule. */
	assert(skipped == 2);
	assert(cfg.rule_count == 1);
	assert(strategy_for_domain(&cfg, "discord.com") == STRATEGY_PASS);
	assert(strategy_for_domain(&cfg, "roblox.com") == STRATEGY_SPLIT);
}

static void	test_name_roundtrip(void)
{
	t_strategy	s;

	assert(strategy_from_name("SpLiT", &s) == 0);
	assert(s == STRATEGY_SPLIT);
	assert(strcmp(strategy_name(STRATEGY_SPLIT), "split") == 0);
	assert(strategy_from_name("not-a-strategy", &s) != 0);
}

static void	test_chain_single_action_is_safe(void)
{
	t_strategy_chain	chain;

	assert(strategy_chain_from_string("split", &chain) == 0);
	assert(chain.action_count == 1);
	assert(chain.actions[0] == STRATEGY_SPLIT);
	assert(strategy_chain_is_safe(&chain));
}

static void	test_chain_fake_split_order_preserved(void)
{
	t_strategy_chain	a;
	t_strategy_chain	b;

	assert(strategy_chain_from_string("fake+split", &a) == 0);
	assert(a.action_count == 2);
	assert(a.actions[0] == STRATEGY_FAKE);
	assert(a.actions[1] == STRATEGY_SPLIT);

	assert(strategy_chain_from_string("split+fake", &b) == 0);
	assert(b.action_count == 2);
	assert(b.actions[0] == STRATEGY_SPLIT);
	assert(b.actions[1] == STRATEGY_FAKE);

	/* Same two actions, different order — must NOT be treated as
	 * equal; nfqueue_engine.c executes them with different observable
	 * wire behavior. */
	assert(a.actions[0] != b.actions[0]);
}

static void	test_chain_split_disorder_normalizes_to_disorder(void)
{
	t_strategy_chain	chain;

	assert(strategy_chain_from_string("split+disorder", &chain) == 0);
	assert(chain.action_count == 1);
	assert(chain.actions[0] == STRATEGY_DISORDER);
}

static void	test_chain_rejects_unsafe_combination(void)
{
	t_strategy_chain	chain;

	/* fake+disorder / disorder+fake / fragment+anything are not in
	 * the safe whitelist. */
	assert(strategy_chain_from_string("fake+disorder", &chain) != 0);
	assert(strategy_chain_from_string("disorder+fake", &chain) != 0);
	assert(strategy_chain_from_string("fragment+split", &chain) != 0);
	assert(strategy_chain_from_string("split+fragment", &chain) != 0);
}

static void	test_chain_rejects_too_many_actions(void)
{
	t_strategy_chain	chain;

	assert(strategy_chain_from_string("split+fake+disorder", &chain) != 0);
}

static void	test_chain_rejects_unknown_action_name(void)
{
	t_strategy_chain	chain;

	assert(strategy_chain_from_string("split+bogus", &chain) != 0);
	assert(strategy_chain_from_string("bogus", &chain) != 0);
	assert(strategy_chain_from_string("split+", &chain) != 0);
	assert(strategy_chain_from_string("+split", &chain) != 0);
}

static void	test_chain_describe_roundtrip(void)
{
	t_strategy_chain	chain;
	char				buf[32];

	assert(strategy_chain_from_string("fake+split", &chain) == 0);
	strategy_chain_describe(&chain, buf, sizeof(buf));
	assert(strcmp(buf, "fake+split") == 0);
}

static void	test_config_parses_chain_domain_rule(void)
{
	t_strategy_config	cfg;
	const char			*text =
		"default = pass\n"
		"[domains]\n"
		"example.com = split+fake\n"
		"discord.com = fake+split\n"
		"roblox.com = split+disorder\n"
		"bad.example = fake+disorder\n";
	t_strategy_chain	chain;

	strategy_config_init(&cfg);
	/* exactly one line ("bad.example = fake+disorder") is skipped as
	 * an unsafe combination. */
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 1);

	strategy_chain_for_domain(&cfg, "example.com", &chain);
	assert(chain.action_count == 2);
	assert(chain.actions[0] == STRATEGY_SPLIT);
	assert(chain.actions[1] == STRATEGY_FAKE);

	strategy_chain_for_domain(&cfg, "discord.com", &chain);
	assert(chain.action_count == 2);
	assert(chain.actions[0] == STRATEGY_FAKE);
	assert(chain.actions[1] == STRATEGY_SPLIT);

	strategy_chain_for_domain(&cfg, "roblox.com", &chain);
	assert(chain.action_count == 1);
	assert(chain.actions[0] == STRATEGY_DISORDER);

	/* the rejected line never created a rule, so this domain falls
	 * through to the default (pass). */
	strategy_chain_for_domain(&cfg, "bad.example", &chain);
	assert(chain.action_count == 1);
	assert(chain.actions[0] == STRATEGY_PASS);
}

static void	test_config_parses_fake_ttl(void)
{
	t_strategy_config	cfg;
	const char			*text = "fake_ttl = 12\n";

	strategy_config_init(&cfg);
	assert(cfg.fake_ttl == STRATEGY_DEFAULT_FAKE_TTL);
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 0);
	assert(cfg.fake_ttl == 12);
}

static void	test_config_rejects_invalid_fake_ttl(void)
{
	t_strategy_config	cfg;
	const char			*text = "fake_ttl = 0\n";

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, text, strlen(text)) == 1);
	assert(cfg.fake_ttl == STRATEGY_DEFAULT_FAKE_TTL);
}

int	main(void)
{
	test_default_is_pass();
	test_spec_example_config();
	test_malformed_lines_are_skipped_safely();
	test_empty_config_stays_safe();
	test_suffix_match();
	test_exact_rule_beats_suffix_rule();
	test_duplicate_rule_last_write_wins();
	test_comments_and_blank_lines_ignored();
	test_unknown_section_is_skipped_safely();
	test_name_roundtrip();
	test_chain_single_action_is_safe();
	test_chain_fake_split_order_preserved();
	test_chain_split_disorder_normalizes_to_disorder();
	test_chain_rejects_unsafe_combination();
	test_chain_rejects_too_many_actions();
	test_chain_rejects_unknown_action_name();
	test_chain_describe_roundtrip();
	test_config_parses_chain_domain_rule();
	test_config_parses_fake_ttl();
	test_config_rejects_invalid_fake_ttl();
	printf("test_strategy: OK\n");
	return (0);
}
