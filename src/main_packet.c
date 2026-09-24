#include "capabilities.h"
#include "discovery.h"
#include "nfqueue_engine.h"
#include "nft_rules.h"
#include "strategy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef DPI_PROXY_VERSION
# define DPI_PROXY_VERSION "0.0.0-dev"
#endif

/* Set by --json, checked by the read-only reporting commands
 * (--show-strategy/--status) so a script or another program gets
 * stable, parseable output instead of having to scrape human-
 * formatted text. The human text format is still the default and is
 * not going away; --json is strictly additive. */
static int	g_json_output = 0;

/* Minimal JSON string escaping: backslash, double-quote, and control
 * characters below 0x20 (domain names/SSIDs are the only free-text
 * fields this ever wraps, but this doesn't assume that — anything
 * unexpected is escaped rather than trusted). Writes into a
 * caller-owned buffer, always NUL-terminated, silently truncating
 * (never overflowing) if `out_size` is too small. */
static void	json_escape(const char *in, char *out, size_t out_size)
{
	size_t	i;
	size_t	pos;

	i = 0;
	pos = 0;
	while (in[i] != '\0' && pos + 2 < out_size)
	{
		if (in[i] == '"' || in[i] == '\\')
		{
			out[pos++] = '\\';
			out[pos++] = in[i];
		}
		else if ((unsigned char)in[i] < 0x20)
			pos += (size_t)snprintf(out + pos, out_size - pos, "\\u%04x",
					in[i]);
		else
			out[pos++] = in[i];
		i++;
	}
	out[pos] = '\0';
}

/* Same default-path/env-override convention strategy.conf already
 * uses (see load_strategy_config() in nfqueue_engine.c) — kept as a
 * small, separate, bounded (8KB) read here rather than exported from
 * that file, since these CLI actions never need the full engine. A
 * missing file just means an empty config (default PASS), same
 * fail-safe posture as the live engine. */
static void	load_strategy_config_from_disk(t_strategy_config *cfg)
{
	const char	*path;
	FILE		*f;
	char		buf[8192];
	size_t		n;

	strategy_config_init(cfg);
	path = getenv("DPI_PROXY_STRATEGY_CONF");
	if (path == NULL)
		path = "strategy.conf";
	f = fopen(path, "r");
	if (f == NULL)
		return ;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	strategy_config_parse(cfg, buf, n);
}

static const char	*discovery_cache_path(void)
{
	const char	*path;

	path = getenv("DPI_PROXY_DISCOVERY_CACHE");
	if (path == NULL)
		path = "discovery-cache.conf";
	return (path);
}

static void	load_discovery_cache_from_disk(t_discovery_cache *cache)
{
	if (discovery_cache_load_file(cache, discovery_cache_path()) < 0)
		fprintf(stderr, "warning: could not read discovery cache %s\n",
			discovery_cache_path());
}

static int	save_discovery_cache_to_disk(const t_discovery_cache *cache)
{
	return (discovery_cache_save_file(cache, discovery_cache_path()));
}

/* Read-only, needs no privilege at all: manual rule (strategy.conf)
 * always wins, then a fresh same-network cached discovery result,
 * then the config's own default. Never touches the network or
 * nftables. */
static void	print_show_strategy_json(const char *domain, const char *chain,
	const char *source, int64_t validated_ago_seconds)
{
	char	domain_esc[320];
	char	chain_esc[128];

	json_escape(domain, domain_esc, sizeof(domain_esc));
	json_escape(chain, chain_esc, sizeof(chain_esc));
	printf("{\"domain\":\"%s\",\"chain\":\"%s\",\"source\":\"%s\"",
		domain_esc, chain_esc, source);
	if (validated_ago_seconds >= 0)
		printf(",\"validated_ago_seconds\":%lld",
			(long long)validated_ago_seconds);
	printf("}\n");
}

static int	cmd_show_strategy(const char *domain)
{
	t_strategy_config				cfg;
	t_discovery_cache				cache;
	t_strategy_chain				chain;
	const t_discovery_cache_entry	*entry;
	t_strategy_source				source;
	char							desc[64];
	int64_t							now;

	load_strategy_config_from_disk(&cfg);
	load_discovery_cache_from_disk(&cache);
	now = (int64_t)time(NULL);
	source = strategy_resolve_chain(&cfg, &cache, netfingerprint_current(),
			now, domain, &chain, &entry);
	strategy_chain_describe(&chain, desc, sizeof(desc));
	if (g_json_output)
		print_show_strategy_json(domain, desc, strategy_source_name(source),
			entry != NULL ? now - entry->validated_at : -1);
	else if (source == STRATEGY_SOURCE_MANUAL)
		printf("%s: %s (source: manual, strategy.conf)\n", domain, desc);
	else if (source == STRATEGY_SOURCE_AUTO)
		printf("%s: %s (source: auto-discovery, validated %llds ago on "
			"this network)\n", domain, desc,
			(long long)(now - entry->validated_at));
	else
		printf("%s: %s (source: default — no manual rule and no fresh "
			"cached discovery for this network; run \"--probe %s\" to "
			"auto-discover one)\n", domain, desc, domain);
	return (0);
}

#ifdef HAVE_NFQUEUE_ENGINE
/* --probe / --reprobe. Requires the same CAP_NET_ADMIN/CAP_NET_RAW as
 * running the engine itself — see probe_via_live_engine()
 * (src/discovery/probe_runner.c) for exactly what this does and its
 * live-validation status. `force` (true for --reprobe) skips the
 * cache-freshness check and always runs a new probe. */
static int	cmd_probe(const char *domain, int force)
{
	t_strategy_config				cfg;
	t_discovery_cache				cache;
	t_strategy_chain				manual_chain;
	t_strategy_chain				found_chain;
	const t_discovery_cache_entry	*entry;
	char							desc[64];
	uint64_t						fp;
	int64_t							now;
	uint8_t							fake_ttl;
	t_probe_result					last;

	load_strategy_config_from_disk(&cfg);
	if (strategy_has_explicit_rule(&cfg, domain, &manual_chain))
	{
		strategy_chain_describe(&manual_chain, desc, sizeof(desc));
		printf("%s: manual override already set in strategy.conf "
			"(\"%s\") — auto-discovery never overrides an explicit "
			"rule; remove it there first if you want discovery to "
			"choose instead.\n", domain, desc);
		return (1);
	}

	load_discovery_cache_from_disk(&cache);
	fp = netfingerprint_current();
	now = (int64_t)time(NULL);
	if (!force)
	{
		entry = discovery_cache_lookup(&cache, domain, fp,
				DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, now);
		if (entry != NULL)
		{
			strategy_chain_describe(&entry->chain, desc, sizeof(desc));
			printf("%s: already have a fresh cached result (\"%s\", "
				"validated %llds ago on this network) — use --reprobe "
				"to force a new probe.\n", domain, desc,
				(long long)(now - entry->validated_at));
			return (0);
		}
	}

	printf("Probing %s — this applies real, temporary packet "
		"manipulation to a test connection and needs the same "
		"CAP_NET_ADMIN/CAP_NET_RAW the engine normally needs (see "
		"--capabilities).\n", domain);
	fake_ttl = cfg.fake_ttl;
	if (discovery_run(domain, probe_via_live_engine, &fake_ttl, 6000,
			&found_chain, &last))
	{
		strategy_chain_describe(&found_chain, desc, sizeof(desc));
		discovery_cache_set(&cache, domain, &found_chain, fp, now);
		if (save_discovery_cache_to_disk(&cache) < 0)
			fprintf(stderr, "warning: could not save discovery cache "
				"to %s\n", discovery_cache_path());
		printf("%s: selected \"%s\" (cached for this network in %s)\n",
			domain, desc, discovery_cache_path());
		return (0);
	}

	printf("%s: no candidate strategy succeeded (last result: %s) — "
		"nothing cached. Either this domain isn't reachable at all "
		"right now, or every strategy this project implements was "
		"rejected; nothing was left applied to your traffic.\n",
		domain, probe_result_name(last));
	return (1);
}
#endif

/* --status: everything human-readable in one place — current
 * network, current profile (fingerprint), manual overrides, and
 * auto-discovered strategies that are actually fresh for this network
 * right now. Read-only, no privilege needed (same posture as
 * --show-strategy). */
static void	print_status_json(const t_net_profile *profile, uint64_t fp,
	const t_strategy_config *cfg, const t_discovery_cache *cache,
	int64_t now)
{
	char	esc[320];
	size_t	i;
	int		first;

	printf("{\"network\":{\"iface\":\"%s\",\"link_type\":\"%s\","
		"\"ssid\":\"", profile->iface, link_type_name(profile->link_type));
	json_escape(profile->ssid, esc, sizeof(esc));
	printf("%s\",\"ipv4\":%s,\"ipv6\":%s,\"local_addr\":\"%s\"},\n",
		esc, profile->has_ipv4_default ? "true" : "false",
		profile->has_ipv6_default ? "true" : "false", profile->local_addr);

	if (fp == NETFP_UNKNOWN)
		printf(" \"profile\":null,\n");
	else
		printf(" \"profile\":\"%016llx\",\n", (unsigned long long)fp);

	printf(" \"default_strategy\":\"%s\",\n",
		strategy_name(cfg->default_strategy));

	printf(" \"manual_overrides\":[");
	i = 0;
	first = 1;
	while (i < cfg->rule_count)
	{
		char	chain_desc[64];

		strategy_chain_describe(&cfg->rules[i].chain, chain_desc,
			sizeof(chain_desc));
		json_escape(cfg->rules[i].domain, esc, sizeof(esc));
		printf("%s{\"domain\":\"%s\",\"chain\":\"%s\"}",
			first ? "" : ",", esc, chain_desc);
		first = 0;
		i++;
	}
	printf("],\n");

	printf(" \"cached_strategies\":[");
	i = 0;
	first = 1;
	while (i < cache->count)
	{
		const t_discovery_cache_entry	*entry;

		entry = discovery_cache_lookup(cache, cache->entries[i].domain, fp,
				DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, now);
		if (entry != NULL)
		{
			char	chain_desc[64];

			strategy_chain_describe(&entry->chain, chain_desc,
				sizeof(chain_desc));
			json_escape(entry->domain, esc, sizeof(esc));
			printf("%s{\"domain\":\"%s\",\"chain\":\"%s\","
				"\"validated_ago_seconds\":%lld}", first ? "" : ",", esc,
				chain_desc, (long long)(now - entry->validated_at));
			first = 0;
		}
		i++;
	}
	printf("]}\n");
}

static int	cmd_status(void)
{
	t_net_profile					profile;
	char							desc[256];
	t_strategy_config				cfg;
	t_discovery_cache				cache;
	uint64_t						fp;
	int64_t							now;
	size_t							i;
	int								any;
	char							chain_desc[64];

	netprofile_gather(&profile);
	netprofile_describe(&profile, desc, sizeof(desc));
	fp = netfingerprint_current();
	now = (int64_t)time(NULL);

	if (g_json_output)
	{
		load_strategy_config_from_disk(&cfg);
		load_discovery_cache_from_disk(&cache);
		print_status_json(&profile, fp, &cfg, &cache, now);
		return (0);
	}

	printf("Network: %s\n", desc);
	if (fp == NETFP_UNKNOWN)
		printf("Profile: unknown (no default route detected — discovery "
			"cache lookups will always miss)\n");
	else
		printf("Profile: %016llx\n", (unsigned long long)fp);

	load_strategy_config_from_disk(&cfg);
	printf("\nManual overrides (%s):\n",
		getenv("DPI_PROXY_STRATEGY_CONF") != NULL
			? getenv("DPI_PROXY_STRATEGY_CONF") : "strategy.conf");
	if (cfg.rule_count == 0)
		printf("  (none — everything defaults to \"%s\")\n",
			strategy_name(cfg.default_strategy));
	else
	{
		i = 0;
		while (i < cfg.rule_count)
		{
			strategy_chain_describe(&cfg.rules[i].chain, chain_desc,
				sizeof(chain_desc));
			printf("  %-40s %s\n", cfg.rules[i].domain, chain_desc);
			i++;
		}
		printf("  (everything else defaults to \"%s\")\n",
			strategy_name(cfg.default_strategy));
	}

	printf("\nAuto-discovered strategies fresh for this network (%s):\n",
		discovery_cache_path());
	load_discovery_cache_from_disk(&cache);
	any = 0;
	i = 0;
	while (i < cache.count)
	{
		const t_discovery_cache_entry	*entry;

		entry = discovery_cache_lookup(&cache, cache.entries[i].domain, fp,
				DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, now);
		if (entry != NULL)
		{
			strategy_chain_describe(&entry->chain, chain_desc,
				sizeof(chain_desc));
			printf("  %-40s %s (validated %llds ago)\n", entry->domain,
				chain_desc, (long long)(now - entry->validated_at));
			any = 1;
		}
		i++;
	}
	if (!any)
		printf("  (none yet for this network — run \"--probe DOMAIN\")\n");

	return (0);
}

/* --export-profile PATH: dumps the discovery cache, re-serialized
 * (validating it round-trips), to PATH — a portable text file another
 * machine's --import-profile can load. --import-profile PATH: merges
 * PATH's entries into the existing cache (discovery_cache_parse's
 * usual last-write-wins duplicate handling) and saves the result. */
static int	cmd_export_profile(const char *path)
{
	t_discovery_cache	cache;
	char				buf[16384];
	size_t				written;
	FILE				*f;

	load_discovery_cache_from_disk(&cache);
	written = discovery_cache_serialize(&cache, buf, sizeof(buf));
	f = fopen(path, "w");
	if (f == NULL)
	{
		fprintf(stderr, "could not open %s for writing\n", path);
		return (1);
	}
	fwrite(buf, 1, written, f);
	fclose(f);
	printf("Exported %zu cached strategy(ies) to %s\n", cache.count, path);
	return (0);
}

static int	cmd_import_profile(const char *path)
{
	t_discovery_cache	cache;
	FILE				*f;
	char				buf[16384];
	size_t				n;
	size_t				skipped;

	load_discovery_cache_from_disk(&cache);
	f = fopen(path, "r");
	if (f == NULL)
	{
		fprintf(stderr, "could not open %s for reading\n", path);
		return (1);
	}
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	skipped = discovery_cache_parse(&cache, buf, n);
	if (save_discovery_cache_to_disk(&cache) < 0)
	{
		fprintf(stderr, "could not save merged cache to %s\n",
			discovery_cache_path());
		return (1);
	}
	printf("Imported from %s: %zu strategy(ies) now cached for this "
		"machine (%zu line(s) skipped as malformed). Entries only take "
		"effect on a network whose fingerprint matches — run --status "
		"to see what's actually fresh right now.\n", path, cache.count,
		skipped);
	return (0);
}

static void	print_usage(const char *argv0)
{
	printf("Usage: %s [options]\n"
		"\n"
		"Linux transparent packet-mode DPI engine (nftables + NFQUEUE).\n"
		"Requires CAP_NET_ADMIN/CAP_NET_RAW (or root) to actually run —\n"
		"see --capabilities to check what this process currently has.\n"
		"\n"
		"Options:\n"
		"  --mode packet        this binary only ever runs packet mode;\n"
		"                       for the portable proxy see dpi-proxy\n"
		"  --config PATH        strategy config file (default: "
		"./strategy.conf,\n"
		"                       same as DPI_PROXY_STRATEGY_CONF; missing "
		"file\n"
		"                       just means everything defaults to PASS)\n"
		"  --discovery-cache PATH   discovery cache file (default: "
		"./discovery-cache.conf,\n"
		"                       same as DPI_PROXY_DISCOVERY_CACHE)\n"
		"  --log-level LEVEL    error|warn|info|debug (default: warn)\n"
		"  --probe DOMAIN       auto-discover a working strategy for "
		"DOMAIN\n"
		"                       (skips if a fresh cached result "
		"exists for this\n"
		"                       network); needs the same "
		"CAP_NET_ADMIN/CAP_NET_RAW\n"
		"                       as running the engine\n"
		"  --reprobe DOMAIN     like --probe, but always runs a new "
		"probe\n"
		"  --show-strategy DOMAIN   print which strategy would apply "
		"to DOMAIN\n"
		"                       right now and why (manual/cached/"
		"default) —\n"
		"                       read-only, no privilege needed\n"
		"  --status             print current network profile, manual "
		"overrides,\n"
		"                       and fresh auto-discovered strategies — "
		"read-only\n"
		"  --export-profile PATH    save the discovery cache to PATH\n"
		"  --import-profile PATH    merge PATH into the discovery "
		"cache\n"
		"  --json               make --show-strategy/--status print "
		"JSON\n"
		"                       instead of human text (for scripting)\n"
		"  --capabilities       print a platform/capability report and exit\n"
		"  --version            print the version and exit\n"
		"  --help               print this message and exit\n"
		"\n"
		"Example:\n"
		"  sudo setcap cap_net_admin,cap_net_raw+eip %s\n"
		"  %s --config strategy.conf --log-level info\n",
		argv0, argv0, argv0);
}

static void	print_capabilities(void)
{
	int	net_admin;
	int	net_raw;
	int	raw_socket;
	int	has_nft;
	int	built;

	capabilities_probe_linux(&net_admin, &net_raw, &raw_socket);
	has_nft = capabilities_has_nft();
#ifdef HAVE_NFQUEUE_ENGINE
	built = 1;
#else
	built = 0;
#endif

	printf("platform: %s\n", capabilities_platform());
	printf("proxy_mode: not built into this binary (see dpi-proxy)\n");
	printf("packet_mode: %s\n", built
		? "built (libnetfilter_queue linked)"
		: "NOT built — rebuild with `make packet-mode`");
	printf("cap_net_admin: %s\n", net_admin ? "yes" : "no");
	printf("cap_net_raw: %s\n", net_raw ? "yes" : "no");
	printf("raw_socket: %s\n", raw_socket ? "yes" : "no");
	printf("nft_binary_found: %s\n", has_nft ? "yes" : "no");
	printf("ipv4: yes (PASS, SPLIT, DISORDER, FAKE, FRAGMENT, and the "
		"fake+split/split+fake chains)\n");
	printf("ipv6: yes (PASS/classification only — no wire-modifying "
		"strategy is wired to IPv6 yet)\n");
	printf("tls_strategies: %s\n", built
		? "yes (IPv4, single-packet ClientHello only — see "
			"docs/packet-mode.md)"
		: "no (not built)");

	if (built && (!net_admin || !net_raw))
		printf("\nNote: missing capabilities above will make startup "
			"fail at nftables/NFQUEUE setup. See README \"Packet mode\" "
			"for the setcap/sudo commands.\n");
	if (!has_nft)
		printf("\nNote: no `nft` binary found — install the `nftables` "
			"package.\n");
}

/* Deferred action requested via a domain-taking flag (--show-strategy/
 * --probe/--reprobe) — executed only after the whole argv has been
 * parsed (see the end of main()), so a flag like --config or
 * --discovery-cache still takes effect regardless of which side of
 * the action flag it appears on in the command line. */
typedef enum e_deferred_action
{
	ACTION_NONE = 0,
	ACTION_SHOW_STRATEGY,
	ACTION_PROBE,
	ACTION_REPROBE,
	ACTION_STATUS,
	ACTION_EXPORT_PROFILE,
	ACTION_IMPORT_PROFILE
}	t_deferred_action;

int	main(int argc, char **argv)
{
	int					i;
	int					queue_num;
	t_deferred_action	action;
	const char			*action_domain;

	queue_num = NFT_DEFAULT_QUEUE_NUM;
	action = ACTION_NONE;
	action_domain = NULL;
	i = 1;
	while (i < argc)
	{
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
		{
			print_usage(argv[0]);
			return (0);
		}
		else if (strcmp(argv[i], "--version") == 0)
		{
			printf("dpi-proxy-packet %s\n", DPI_PROXY_VERSION);
			return (0);
		}
		else if (strcmp(argv[i], "--capabilities") == 0)
		{
			print_capabilities();
			return (0);
		}
		else if (strcmp(argv[i], "--show-strategy") == 0 && i + 1 < argc)
		{
			i++;
			action = ACTION_SHOW_STRATEGY;
			action_domain = argv[i];
		}
		else if (strcmp(argv[i], "--probe") == 0 && i + 1 < argc)
		{
			i++;
			action = ACTION_PROBE;
			action_domain = argv[i];
		}
		else if (strcmp(argv[i], "--reprobe") == 0 && i + 1 < argc)
		{
			i++;
			action = ACTION_REPROBE;
			action_domain = argv[i];
		}
		else if (strcmp(argv[i], "--status") == 0)
		{
			action = ACTION_STATUS;
		}
		else if (strcmp(argv[i], "--json") == 0)
		{
			g_json_output = 1;
		}
		else if (strcmp(argv[i], "--export-profile") == 0 && i + 1 < argc)
		{
			i++;
			action = ACTION_EXPORT_PROFILE;
			action_domain = argv[i]; /* reused as a path here */
		}
		else if (strcmp(argv[i], "--import-profile") == 0 && i + 1 < argc)
		{
			i++;
			action = ACTION_IMPORT_PROFILE;
			action_domain = argv[i]; /* reused as a path here */
		}
		else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
		{
			i++;
			setenv("DPI_PROXY_STRATEGY_CONF", argv[i], 1);
		}
		else if (strcmp(argv[i], "--discovery-cache") == 0 && i + 1 < argc)
		{
			i++;
			setenv("DPI_PROXY_DISCOVERY_CACHE", argv[i], 1);
		}
		else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc)
		{
			i++;
			if (strcmp(argv[i], "error") != 0 && strcmp(argv[i], "warn") != 0
				&& strcmp(argv[i], "info") != 0
				&& strcmp(argv[i], "debug") != 0)
			{
				fprintf(stderr, "unknown --log-level \"%s\" (expected "
					"error, warn, info, or debug)\n", argv[i]);
				return (1);
			}
			setenv("DPI_PROXY_LOG_LEVEL", argv[i], 1);
		}
		else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
		{
			i++;
			if (strcmp(argv[i], "packet") != 0)
			{
				fprintf(stderr, "this binary only supports --mode packet; "
					"for the portable SOCKS5 proxy, use dpi-proxy\n");
				return (1);
			}
		}
		else
		{
			fprintf(stderr, "unknown option: %s (see --help)\n", argv[i]);
			return (1);
		}
		i++;
	}

	if (action == ACTION_SHOW_STRATEGY)
		return (cmd_show_strategy(action_domain) != 0);
	if (action == ACTION_STATUS)
		return (cmd_status() != 0);
	if (action == ACTION_EXPORT_PROFILE)
		return (cmd_export_profile(action_domain) != 0);
	if (action == ACTION_IMPORT_PROFILE)
		return (cmd_import_profile(action_domain) != 0);
	if (action == ACTION_PROBE || action == ACTION_REPROBE)
	{
#ifdef HAVE_NFQUEUE_ENGINE
		return (cmd_probe(action_domain, action == ACTION_REPROBE) != 0);
#else
		fprintf(stderr, "packet mode was not built with "
			"HAVE_NFQUEUE_ENGINE — run `make packet-mode`. See "
			"--capabilities for what's missing.\n");
		return (1);
#endif
	}

#ifdef HAVE_NFQUEUE_ENGINE
	if (nfqueue_engine_run(queue_num) != 0)
		return (1);
	return (0);
#else
	(void)queue_num;
	fprintf(stderr, "packet mode was not built with HAVE_NFQUEUE_ENGINE "
		"— run `make packet-mode`, not this binary directly. See "
		"--capabilities for what's missing.\n");
	return (1);
#endif
}
