#include "discovery.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---- cache tests ---- */

static void	test_cache_set_and_lookup(void)
{
	t_discovery_cache		cache;
	t_strategy_chain		chain;
	const t_discovery_cache_entry	*entry;

	discovery_cache_init(&cache);
	assert(strategy_chain_from_string("split", &chain) == 0);
	assert(discovery_cache_set(&cache, "example.com", &chain, 1234,
			1000) == 0);

	entry = discovery_cache_lookup(&cache, "example.com", 1234,
			DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, 1500);
	assert(entry != NULL);
	assert(entry->chain.action_count == 1);
	assert(entry->chain.actions[0] == STRATEGY_SPLIT);
}

static void	test_cache_miss_on_unknown_domain(void)
{
	t_discovery_cache	cache;

	discovery_cache_init(&cache);
	assert(discovery_cache_lookup(&cache, "nowhere.example", 1234,
			DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, 1000) == NULL);
}

static void	test_cache_miss_on_fingerprint_mismatch(void)
{
	t_discovery_cache	cache;
	t_strategy_chain	chain;

	discovery_cache_init(&cache);
	strategy_chain_from_string("fake", &chain);
	discovery_cache_set(&cache, "example.com", &chain, 1111, 1000);

	/* same domain, different network → must NOT reuse the old
	 * decision (the whole point of scoping by fingerprint). */
	assert(discovery_cache_lookup(&cache, "example.com", 2222,
			DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, 1500) == NULL);
}

static void	test_cache_miss_on_unknown_fingerprint(void)
{
	t_discovery_cache	cache;
	t_strategy_chain	chain;

	discovery_cache_init(&cache);
	strategy_chain_from_string("fake", &chain);
	discovery_cache_set(&cache, "example.com", &chain, NETFP_UNKNOWN, 1000);

	/* NETFP_UNKNOWN must never be treated as a stable, matchable
	 * network — a lookup asking for NETFP_UNKNOWN must still miss. */
	assert(discovery_cache_lookup(&cache, "example.com", NETFP_UNKNOWN,
			DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, 1500) == NULL);
}

static void	test_cache_miss_on_expiry(void)
{
	t_discovery_cache	cache;
	t_strategy_chain	chain;

	discovery_cache_init(&cache);
	strategy_chain_from_string("split", &chain);
	discovery_cache_set(&cache, "example.com", &chain, 1234, 1000);

	assert(discovery_cache_lookup(&cache, "example.com", 1234, 100,
			1000 + 100) != NULL); /* exactly at TTL boundary: still fresh */
	assert(discovery_cache_lookup(&cache, "example.com", 1234, 100,
			1000 + 101) == NULL); /* one second past TTL: expired */
}

static void	test_cache_miss_on_clock_going_backwards(void)
{
	t_discovery_cache	cache;
	t_strategy_chain	chain;

	discovery_cache_init(&cache);
	strategy_chain_from_string("split", &chain);
	discovery_cache_set(&cache, "example.com", &chain, 1234, 5000);

	/* `now` before validated_at (clock skew / manual clock change):
	 * never trust it rather than compute a nonsensical negative age. */
	assert(discovery_cache_lookup(&cache, "example.com", 1234,
			DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, 4000) == NULL);
}

static void	test_cache_set_updates_existing_entry(void)
{
	t_discovery_cache	cache;
	t_strategy_chain	split_chain;
	t_strategy_chain	fake_chain;

	discovery_cache_init(&cache);
	strategy_chain_from_string("split", &split_chain);
	strategy_chain_from_string("fake", &fake_chain);

	discovery_cache_set(&cache, "example.com", &split_chain, 1234, 1000);
	discovery_cache_set(&cache, "example.com", &fake_chain, 1234, 2000);

	assert(cache.count == 1);
	assert(discovery_cache_lookup(&cache, "example.com", 1234,
			DISCOVERY_CACHE_DEFAULT_TTL_SECONDS,
			2000)->chain.actions[0] == STRATEGY_FAKE);
}

static void	test_cache_serialize_parse_roundtrip(void)
{
	t_discovery_cache	cache;
	t_discovery_cache	loaded;
	t_strategy_chain	chain1;
	t_strategy_chain	chain2;
	char				buf[1024];
	size_t				written;
	size_t				skipped;

	discovery_cache_init(&cache);
	strategy_chain_from_string("split", &chain1);
	strategy_chain_from_string("fake+split", &chain2);
	discovery_cache_set(&cache, "example.com", &chain1, 0xDEADBEEF, 1700000000);
	discovery_cache_set(&cache, "discord.com", &chain2, 0xCAFEBABE, 1700000100);

	written = discovery_cache_serialize(&cache, buf, sizeof(buf));
	assert(written > 0);

	discovery_cache_init(&loaded);
	skipped = discovery_cache_parse(&loaded, buf, written);
	assert(skipped == 0);
	assert(loaded.count == 2);

	assert(discovery_cache_lookup(&loaded, "example.com", 0xDEADBEEF,
			DISCOVERY_CACHE_DEFAULT_TTL_SECONDS,
			1700000000)->chain.actions[0] == STRATEGY_SPLIT);
	{
		const t_discovery_cache_entry	*e;

		e = discovery_cache_lookup(&loaded, "discord.com", 0xCAFEBABE,
				DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, 1700000100);
		assert(e != NULL);
		assert(e->chain.action_count == 2);
		assert(e->chain.actions[0] == STRATEGY_FAKE);
		assert(e->chain.actions[1] == STRATEGY_SPLIT);
	}
}

static void	test_cache_parse_skips_malformed_lines(void)
{
	t_discovery_cache	cache;
	const char			*text =
		"# comment\n"
		"\n"
		"example.com deadbeef 1000 split\n"
		"not enough fields\n"
		"discord.com nothex 1000 split\n"
		"roblox.com deadbeef notanumber split\n"
		"twitch.tv deadbeef 1000 bogus-strategy\n";
	size_t				skipped;

	discovery_cache_init(&cache);
	skipped = discovery_cache_parse(&cache, text, strlen(text));
	assert(skipped == 4);
	assert(cache.count == 1);
}

/* ---- ladder / discovery_run tests ---- */

static t_probe_result	always_reject(const char *domain,
	const t_strategy_chain *candidate, int timeout_ms, void *userdata)
{
	(void)domain;
	(void)candidate;
	(void)timeout_ms;
	(void)userdata;
	return (PROBE_REMOTE_REJECTED);
}

static void	test_discovery_run_exhausts_ladder_when_nothing_works(void)
{
	t_strategy_chain	out;
	t_probe_result		last;
	int					attempts_expected;

	attempts_expected = DISCOVERY_LADDER_LEN
		* DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE;
	(void)attempts_expected;
	assert(discovery_run("example.com", always_reject, NULL, 1000, &out,
			&last) == 0);
	assert(last == PROBE_REMOTE_REJECTED);
}

/* Succeeds on the 3rd ladder entry (FAKE) — proves "pick the
 * simplest working strategy" by never even trying DISORDER/FRAGMENT/
 * the chains once FAKE (index 2) succeeds. */
static t_probe_result	succeed_on_fake(const char *domain,
	const t_strategy_chain *candidate, int timeout_ms, void *userdata)
{
	int	*calls;

	(void)domain;
	(void)timeout_ms;
	calls = userdata;
	(*calls)++;
	if (candidate->action_count == 1 && candidate->actions[0] == STRATEGY_FAKE)
		return (PROBE_SUCCESS);
	return (PROBE_REMOTE_REJECTED);
}

static void	test_discovery_run_stops_at_first_success(void)
{
	t_strategy_chain	out;
	int					calls;

	calls = 0;
	assert(discovery_run("example.com", succeed_on_fake, &calls, 1000,
			&out, NULL) == 1);
	assert(out.action_count == 1);
	assert(out.actions[0] == STRATEGY_FAKE);
	/* PASS and SPLIT each get retried DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE
	 * times (both REMOTE_REJECTED, never SUCCESS), then FAKE succeeds on
	 * its first attempt: 2 + 2 + 1 = 5 calls, never reaching
	 * DISORDER/FRAGMENT/the chains. */
	assert(calls == 2 * DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE + 1);
}

/* Non-local-error failures (TIMEOUT, REMOTE_REJECTED) must each get
 * retried up to DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE times — a single
 * transient failure shouldn't abandon a candidate immediately. This
 * prober never actually succeeds for anything, so discovery_run()
 * must burn the full documented bound before giving up. */
static t_probe_result	flaky_then_succeeds(const char *domain,
	const t_strategy_chain *candidate, int timeout_ms, void *userdata)
{
	int	*calls;

	(void)domain;
	(void)timeout_ms;
	calls = userdata;
	(*calls)++;
	if (candidate->action_count == 1 && candidate->actions[0] == STRATEGY_PASS)
		return (PROBE_TIMEOUT); /* first candidate: transient failure */
	return (PROBE_REMOTE_REJECTED);
}

static void	test_discovery_run_retries_within_bound(void)
{
	t_strategy_chain	out;
	int					calls;

	calls = 0;
	assert(discovery_run("example.com", flaky_then_succeeds, &calls, 1000,
			&out, NULL) == 0);
	/* Never actually succeeds for any candidate (PASS always times out,
	 * everything else is always rejected), and neither TIMEOUT nor
	 * REMOTE_REJECTED short-circuits the per-candidate retry budget
	 * (only PROBE_LOCAL_ERROR does — see the next test) — so this must
	 * hit exactly the documented hard bound, never more. */
	assert(calls == DISCOVERY_LADDER_LEN
		* DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE);
}

/* A local error must not burn the retry budget on a candidate that
 * never even ran — it should move on immediately. Every single call
 * returns PROBE_LOCAL_ERROR, so if local errors were retried like any
 * other failure, this would take DISCOVERY_LADDER_LEN *
 * DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE calls; since they aren't
 * retried, it must take exactly DISCOVERY_LADDER_LEN. */
static t_probe_result	always_local_error(const char *domain,
	const t_strategy_chain *candidate, int timeout_ms, void *userdata)
{
	int	*calls;

	(void)domain;
	(void)candidate;
	(void)timeout_ms;
	calls = userdata;
	(*calls)++;
	return (PROBE_LOCAL_ERROR);
}

static void	test_discovery_run_local_error_skips_retry(void)
{
	t_strategy_chain	out;
	int					calls;

	calls = 0;
	assert(discovery_run("example.com", always_local_error,
			&calls, 1000, &out, NULL) == 0);
	assert(calls == DISCOVERY_LADDER_LEN);
}

/* ---- runtime selection regression: probe → cache → restart →
 * engine lookup (see strategy_resolve_chain) ---- */

#define DISCORD_FP 0x7f8a9740242fa30cULL

static t_probe_result	succeed_on_split(const char *domain,
	const t_strategy_chain *candidate, int timeout_ms, void *userdata)
{
	(void)domain;
	(void)timeout_ms;
	(void)userdata;
	if (candidate->action_count == 1
		&& candidate->actions[0] == STRATEGY_SPLIT)
		return (PROBE_SUCCESS);
	return (PROBE_REMOTE_REJECTED);
}

static void	temp_cache_path(char *out, size_t out_size)
{
	snprintf(out, out_size, "/tmp/dpi-proxy-test-cache-%ld.conf",
		(long)getpid());
}

/* What `--probe discord.com` does: walk the ladder, cache the winner,
 * save it to the cache file. Returns the saved chain. */
static void	simulate_probe_and_save(const char *path, int64_t now)
{
	t_discovery_cache	cache;
	t_strategy_chain	found;

	assert(discovery_run("discord.com", succeed_on_split, NULL, 1000,
			&found, NULL) == 1);
	assert(found.action_count == 1 && found.actions[0] == STRATEGY_SPLIT);
	assert(discovery_cache_load_file(&cache, path) == 0);
	assert(discovery_cache_set(&cache, "discord.com", &found, DISCORD_FP,
			now) == 0);
	assert(discovery_cache_save_file(&cache, path) == 0);
}

static void	load_default_pass_config(t_strategy_config *cfg)
{
	const char	*conf = "default = pass\n";

	strategy_config_init(cfg);
	assert(strategy_config_parse(cfg, conf, strlen(conf)) == 0);
}

static void	test_probe_selects_split(void)
{
	t_strategy_chain	found;
	t_probe_result		last;

	assert(discovery_run("discord.com", succeed_on_split, NULL, 1000,
			&found, &last) == 1);
	assert(found.action_count == 1);
	assert(found.actions[0] == STRATEGY_SPLIT);
	assert(last == PROBE_SUCCESS);
}

static void	test_cache_persists_to_file(void)
{
	char				path[128];
	t_discovery_cache	reloaded;

	temp_cache_path(path, sizeof(path));
	unlink(path);
	simulate_probe_and_save(path, 5000);

	assert(discovery_cache_load_file(&reloaded, path) == 0);
	assert(reloaded.count == 1);
	assert(strcmp(reloaded.entries[0].domain, "discord.com") == 0);
	assert(reloaded.entries[0].chain.actions[0] == STRATEGY_SPLIT);
	assert(reloaded.entries[0].fingerprint == DISCORD_FP);
	assert(reloaded.entries[0].validated_at == 5000);
	unlink(path);
}

static void	test_missing_cache_file_is_empty_not_error(void)
{
	t_discovery_cache	cache;

	cache.count = 99;
	assert(discovery_cache_load_file(&cache,
			"/nonexistent/dir/discovery-cache.conf") == 0);
	assert(cache.count == 0);
}

/* The original bug: the engine only ever consulted strategy.conf, so
 * a restarted daemon with default=pass and no manual rule classified
 * discord.com as PASS despite a fresh cached "split". */
static void	test_daemon_restart_selects_cached_split(void)
{
	char							path[128];
	t_strategy_config				cfg;
	t_discovery_cache				cache;
	t_strategy_chain				chain;
	const t_discovery_cache_entry	*entry;

	temp_cache_path(path, sizeof(path));
	unlink(path);
	simulate_probe_and_save(path, 5000);

	/* "restart": everything rebuilt from disk, nothing carried over. */
	load_default_pass_config(&cfg);
	assert(discovery_cache_load_file(&cache, path) == 0);

	/* Without the cache the old code path would say PASS... */
	assert(strategy_for_domain(&cfg, "discord.com") == STRATEGY_PASS);
	/* ...the runtime selector must say SPLIT. */
	assert(strategy_resolve_chain(&cfg, &cache, DISCORD_FP, 5060,
			"discord.com", &chain, &entry) == STRATEGY_SOURCE_AUTO);
	assert(chain.action_count == 1);
	assert(chain.actions[0] == STRATEGY_SPLIT);
	assert(entry != NULL && entry->validated_at == 5000);
	unlink(path);
}

static void	test_runtime_selector_scoping(void)
{
	t_strategy_config	cfg;
	t_discovery_cache	cache;
	t_strategy_chain	split;
	t_strategy_chain	chain;

	load_default_pass_config(&cfg);
	discovery_cache_init(&cache);
	strategy_chain_from_string("split", &split);
	discovery_cache_set(&cache, "discord.com", &split, DISCORD_FP, 5000);

	assert(strategy_resolve_chain(&cfg, &cache, DISCORD_FP, 5001,
			"DISCORD.COM", &chain, NULL) == STRATEGY_SOURCE_AUTO);
	assert(chain.actions[0] == STRATEGY_SPLIT);

	/* different network, unknown network, expired, other host, and no
	 * cache at all → config default, never the cached choice */
	assert(strategy_resolve_chain(&cfg, &cache, 0x1234, 5001,
			"discord.com", &chain, NULL) == STRATEGY_SOURCE_DEFAULT);
	assert(chain.action_count == 1 && chain.actions[0] == STRATEGY_PASS);
	assert(strategy_resolve_chain(&cfg, &cache, NETFP_UNKNOWN, 5001,
			"discord.com", &chain, NULL) == STRATEGY_SOURCE_DEFAULT);
	assert(strategy_resolve_chain(&cfg, &cache, DISCORD_FP,
			5000 + DISCOVERY_CACHE_DEFAULT_TTL_SECONDS + 1,
			"discord.com", &chain, NULL) == STRATEGY_SOURCE_DEFAULT);
	assert(strategy_resolve_chain(&cfg, &cache, DISCORD_FP, 5001,
			"example.com", &chain, NULL) == STRATEGY_SOURCE_DEFAULT);
	assert(strategy_resolve_chain(&cfg, NULL, DISCORD_FP, 5001,
			"discord.com", &chain, NULL) == STRATEGY_SOURCE_DEFAULT);
}

static void	test_manual_override_beats_cached_auto(void)
{
	const char						*conf =
		"default = pass\n[domains]\ndiscord.com = fake\n.example.org = "
		"disorder\n";
	t_strategy_config				cfg;
	t_discovery_cache				cache;
	t_strategy_chain				split;
	t_strategy_chain				chain;
	const t_discovery_cache_entry	*entry;

	strategy_config_init(&cfg);
	assert(strategy_config_parse(&cfg, conf, strlen(conf)) == 0);
	discovery_cache_init(&cache);
	strategy_chain_from_string("split", &split);
	discovery_cache_set(&cache, "discord.com", &split, DISCORD_FP, 5000);
	discovery_cache_set(&cache, "www.example.org", &split, DISCORD_FP, 5000);

	assert(strategy_resolve_chain(&cfg, &cache, DISCORD_FP, 5001,
			"discord.com", &chain, &entry) == STRATEGY_SOURCE_MANUAL);
	assert(chain.action_count == 1 && chain.actions[0] == STRATEGY_FAKE);
	assert(entry == NULL);

	/* suffix manual rules win too */
	assert(strategy_resolve_chain(&cfg, &cache, DISCORD_FP, 5001,
			"www.example.org", &chain, NULL) == STRATEGY_SOURCE_MANUAL);
	assert(chain.actions[0] == STRATEGY_DISORDER);

	/* an explicit "= pass" manual rule also beats a cached split */
	{
		const char	*pass_conf = "[domains]\ndiscord.com = pass\n";

		strategy_config_init(&cfg);
		strategy_config_parse(&cfg, pass_conf, strlen(pass_conf));
		assert(strategy_resolve_chain(&cfg, &cache, DISCORD_FP, 5001,
				"discord.com", &chain, NULL) == STRATEGY_SOURCE_MANUAL);
		assert(chain.actions[0] == STRATEGY_PASS);
	}
}

/* The live bug: with DNS pointing discord.com at the ISP's block
 * server, the handshake "completed" with its self-signed
 * CN=localhost.localdomain certificate and the prober called that a
 * success, caching a strategy that never worked. */
static void	test_probe_rejects_intercepted_certificate(void)
{
	const char	*block_page =
		"CONNECTED(00000003)\n"
		"depth=0 C = US, ST = WA, L = Seattle, O = MyCompany, OU = IT, "
		"CN = localhost.localdomain\n"
		"verify error:num=18:self-signed certificate\n"
		"subject=C = US, ST = WA, L = Seattle, O = MyCompany, OU = IT, "
		"CN = localhost.localdomain\n"
		"    Verify return code: 18 (self-signed certificate)\n";
	const char	*real =
		"CONNECTED(00000003)\n"
		"depth=0 CN = discord.com\nverify return:1\n"
		"subject=CN = discord.com\n"
		"issuer=C = US, O = Google Trust Services, CN = WE1\n"
		"    Verify return code: 0 (ok)\n";
	const char	*reset =
		"CONNECTED(00000003)\nwrite:errno=104\n"
		"no peer certificate available\n";

	assert(probe_classify_openssl_output(block_page)
		== PROBE_REMOTE_REJECTED);
	assert(probe_classify_openssl_output(real) == PROBE_SUCCESS);
	assert(probe_classify_openssl_output(reset) == PROBE_REMOTE_REJECTED);
	assert(probe_classify_openssl_output("connect: Connection refused\n")
		== PROBE_LOCAL_ERROR);
	/* a chain-valid certificate for some other name: what s_client
	 * reports with -verify_hostname (real output, openssl 3.0.13,
	 * example.com checked against wrong.invalid) — never a success */
	assert(probe_classify_openssl_output(
			"CONNECTED(00000003)\n"
			"verify error:num=62:hostname mismatch\n"
			"    Verify return code: 62 (hostname mismatch)\n")
		== PROBE_REMOTE_REJECTED);
}

int	main(void)
{
	test_cache_set_and_lookup();
	test_cache_miss_on_unknown_domain();
	test_cache_miss_on_fingerprint_mismatch();
	test_cache_miss_on_unknown_fingerprint();
	test_cache_miss_on_expiry();
	test_cache_miss_on_clock_going_backwards();
	test_cache_set_updates_existing_entry();
	test_cache_serialize_parse_roundtrip();
	test_cache_parse_skips_malformed_lines();
	test_discovery_run_exhausts_ladder_when_nothing_works();
	test_discovery_run_stops_at_first_success();
	test_discovery_run_retries_within_bound();
	test_discovery_run_local_error_skips_retry();
	test_probe_selects_split();
	test_cache_persists_to_file();
	test_missing_cache_file_is_empty_not_error();
	test_daemon_restart_selects_cached_split();
	test_runtime_selector_scoping();
	test_manual_override_beats_cached_auto();
	test_probe_rejects_intercepted_certificate();
	printf("test_discovery: OK\n");
	return (0);
}
