/* ============================================================
 * PASS path: live-tested on Linux with real CAP_NET_ADMIN/
 * CAP_NET_RAW — binds a real NFQUEUE and accepts real HTTP/HTTPS
 * traffic unmodified (verified live: nftables counters, engine log
 * lines, repeated start/stop).
 *
 * SPLIT path (DROP + raw-socket reinject, see inject_ipv4_packet
 * and the NFT_ANTILOOP_MARK loop-prevention below): the highest-risk
 * part of the engine, and the most carefully field-tested — verified
 * against real TLS traffic (packet capture inspected for correct
 * sequence numbers and checksums, no anti-loop re-queue storm,
 * including under a SIGINT sent mid-session). Still the part most
 * worth watching if you change it.
 * ============================================================ */
#ifdef HAVE_NFQUEUE_ENGINE

#include "nfqueue_engine.h"
#include "discovery.h"
#include "nft_rules.h"
#include "flow.h"
#include "http_parse.h"
#include "tls_sni.h"
#include "tls.h"
#include "packet.h"
#include "strategy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Avoided via #include to dodge a known glibc/<linux/socket.h>
 * header clash on some distros; the numeric value is stable Linux
 * ABI (present since 2.6.25) and this is a common defensive idiom
 * for exactly this constant. */
#ifndef SO_MARK
# define SO_MARK 36
#endif

static volatile sig_atomic_t	g_stop = 0;
static volatile sig_atomic_t	g_reload = 0;

static void	on_signal(int signo)
{
	if (signo == SIGHUP)
		g_reload = 1;
	else
		g_stop = 1;
}

typedef enum e_log_level
{
	LOG_ERROR = 0,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG
}	t_log_level;

typedef struct s_engine_stats
{
	unsigned long	packets_seen;
	unsigned long	packets_passed;
	unsigned long	packets_split;
	/* Incremented whenever a SPLIT action executes as part of any
	 * chain (plain "split", or either fake+split/split+fake combo) —
	 * not just the standalone "split" strategy. */
	unsigned long	packets_disorder;
	unsigned long	packets_fragment;
	unsigned long	fake_decoys_sent;
	unsigned long	parse_failures;
	unsigned long	unsupported_packets;
	unsigned long	flows_created;
	unsigned long	flows_expired;
	unsigned long	raw_send_failures;
}	t_engine_stats;

typedef struct s_engine_ctx
{
	t_flow_table		flows;
	t_strategy_config	strategies;
	/* Auto-discovered strategies (DPI_PROXY_DISCOVERY_CACHE) and the
	 * network fingerprint they are matched against — consulted after
	 * manual strategy.conf rules, see strategy_resolve_chain(). */
	t_discovery_cache	discovered;
	uint64_t			fingerprint;
	int64_t				fingerprint_checked_at;
	t_log_level			log_level;
	int					raw_v4_fd;
	t_engine_stats		stats;
}	t_engine_ctx;

/* Fatal setup errors always go to stderr regardless of level (see the
 * plain fprintf calls in nfqueue_engine_run) — this is for everything
 * that should be gateable: LOG_WARN and above by default, LOG_DEBUG
 * only with DPI_PROXY_LOG_LEVEL=debug or the legacy DPI_PROXY_DEBUG=1. */
static void	log_msg(t_engine_ctx *ctx, t_log_level level, const char *fmt, ...)
{
	va_list	ap;

	if (level > ctx->log_level)
		return ;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static t_log_level	log_level_from_env(void)
{
	const char	*env;

	if (getenv("DPI_PROXY_DEBUG") != NULL)
		return (LOG_DEBUG);
	env = getenv("DPI_PROXY_LOG_LEVEL");
	if (env == NULL)
		return (LOG_WARN);
	if (strcmp(env, "error") == 0)
		return (LOG_ERROR);
	if (strcmp(env, "warn") == 0)
		return (LOG_WARN);
	if (strcmp(env, "info") == 0)
		return (LOG_INFO);
	if (strcmp(env, "debug") == 0)
		return (LOG_DEBUG);
	return (LOG_WARN);
}

static void	log_stats(t_engine_ctx *ctx)
{
	log_msg(ctx, LOG_INFO,
		"[stats] packets_seen=%lu packets_passed=%lu packets_split=%lu "
		"packets_disorder=%lu packets_fragment=%lu fake_decoys_sent=%lu "
		"parse_failures=%lu unsupported_packets=%lu flows_created=%lu "
		"flows_expired=%lu raw_send_failures=%lu\n",
		ctx->stats.packets_seen, ctx->stats.packets_passed,
		ctx->stats.packets_split, ctx->stats.packets_disorder,
		ctx->stats.packets_fragment, ctx->stats.fake_decoys_sent,
		ctx->stats.parse_failures,
		ctx->stats.unsupported_packets, ctx->stats.flows_created,
		ctx->stats.flows_expired, ctx->stats.raw_send_failures);
}

static void	build_flow_key_v4(const t_ipv4_view *ip, const t_tcp_view *tcp,
	t_flow_key *key)
{
	memset(key, 0, sizeof(*key));
	key->family = 4;
	memcpy(key->src_addr, &ip->header->src, 4);
	memcpy(key->dst_addr, &ip->header->dst, 4);
	key->src_port = ntohs(tcp->header->src_port);
	key->dst_port = ntohs(tcp->header->dst_port);
}

static void	build_flow_key_v6(const t_ipv6_view *ip, const t_tcp_view *tcp,
	t_flow_key *key)
{
	memset(key, 0, sizeof(*key));
	key->family = 6;
	memcpy(key->src_addr, ip->header->src, 16);
	memcpy(key->dst_addr, ip->header->dst, 16);
	key->src_port = ntohs(tcp->header->src_port);
	key->dst_port = ntohs(tcp->header->dst_port);
}

/* Buffers this segment's payload into the flow's reassembly window
 * and tries to classify it. `*host_out` is set only when this exact
 * call is the one that completes classification (PACKET_OK) — that
 * is the caller's signal that `flow->reasm` now holds a full,
 * just-completed ClientHello/HTTP request it can act on. */
static t_flow_class	classify(t_flow_entry *flow,
	const uint8_t *payload, size_t payload_len,
	char *host_out, size_t host_out_size)
{
	int	status;

	if (flow->classification_done || payload_len == 0)
		return (FLOW_UNCLASSIFIED);

	if (flow_reasm_append(flow, payload, payload_len) < 0)
	{
		flow->classification_done = 1;
		flow->class_hint = FLOW_PASSTHROUGH;
		return (FLOW_PASSTHROUGH);
	}

	status = tls_parse_client_hello_sni(flow->reasm, flow->reasm_len,
			host_out, host_out_size);
	if (status == PACKET_OK)
	{
		flow->classification_done = 1;
		flow->class_hint = FLOW_TLS;
		return (FLOW_TLS);
	}
	if (status == PACKET_ERR_TRUNCATED)
		return (FLOW_UNCLASSIFIED);

	status = http_parse_host(flow->reasm, flow->reasm_len,
			host_out, host_out_size);
	if (status == PACKET_OK)
	{
		flow->classification_done = 1;
		flow->class_hint = FLOW_HTTP;
		return (FLOW_HTTP);
	}
	if (status == PACKET_ERR_TRUNCATED)
		return (FLOW_UNCLASSIFIED);

	flow->classification_done = 1;
	flow->class_hint = FLOW_PASSTHROUGH;
	return (FLOW_PASSTHROUGH);
}

static int	ensure_raw_v4_socket(t_engine_ctx *ctx)
{
	int	one;
	int	mark;

	if (ctx->raw_v4_fd >= 0)
		return (0);

	ctx->raw_v4_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ctx->raw_v4_fd < 0)
		return (-1);

	one = 1;
	if (setsockopt(ctx->raw_v4_fd, IPPROTO_IP, IP_HDRINCL,
			&one, sizeof(one)) < 0)
	{
		close(ctx->raw_v4_fd);
		ctx->raw_v4_fd = -1;
		return (-1);
	}

	mark = NFT_ANTILOOP_MARK;
	if (setsockopt(ctx->raw_v4_fd, SOL_SOCKET, SO_MARK,
			&mark, sizeof(mark)) < 0)
	{
		close(ctx->raw_v4_fd);
		ctx->raw_v4_fd = -1;
		return (-1);
	}

	return (0);
}

static int	inject_ipv4_packet(t_engine_ctx *ctx, const uint8_t *pkt,
	size_t len)
{
	struct sockaddr_in		dst;
	const t_ipv4_header		*ip;

	if (ensure_raw_v4_socket(ctx) < 0)
		return (-1);

	ip = (const t_ipv4_header *)pkt;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = ip->dst;

	return (sendto(ctx->raw_v4_fd, pkt, len, 0,
			(struct sockaddr *)&dst, sizeof(dst)) == (ssize_t)len
		? 0 : -1);
}

/* Injects `buf`/`len` via the raw socket, logging (but never
 * escalating) a failure. Returns 1 on success, 0 on failure —
 * callers decide whether a failed piece is fatal to the chain. */
static int	inject_or_log(t_engine_ctx *ctx, const char *tag,
	const uint8_t *buf, size_t len)
{
	if (inject_ipv4_packet(ctx, buf, len) < 0)
	{
		ctx->stats.raw_send_failures++;
		log_msg(ctx, LOG_ERROR, "[chain] %s injection failed "
			"(errno=%d)\n", tag, errno);
		return (0);
	}
	return (1);
}

/* Builds a FAKE decoy from `template`/`template_len` (any valid
 * IPv4/TCP packet buffer — the original packet, or one of the SPLIT
 * segments already built for a chain) using ctx's configured
 * fake_ttl. Best-effort: failure is logged and reported via
 * *ok = 0, never fatal to whatever chain step called it — a missing
 * decoy is a degradation (fall back to the supported action it was
 * layered onto), not corruption. */
static void	build_decoy(t_engine_ctx *ctx, const uint8_t *template_pkt,
	size_t template_len, uint8_t *out, size_t *out_len, int *ok)
{
	if (packet_make_fake_tcp_v4(template_pkt, template_len,
			ctx->strategies.fake_ttl, out, out_len) != PACKET_OK)
	{
		log_msg(ctx, LOG_WARN, "[chain] fake decoy construction failed, "
			"continuing without it\n");
		*ok = 0;
		return ;
	}
	*ok = 1;
}

/* Only reachable when: family v4, the flow classified as TLS, the
 * whole ClientHello arrived in this single packet (flow->reasm_len ==
 * this packet's own TCP payload length), and the resolved chain is
 * not a plain PASS. Any other case falls through to the caller's
 * default ACCEPT. Returns 1 if it handled the verdict itself (caller
 * must not also verdict), 0 if the caller should fall back to the
 * default ACCEPT.
 *
 * Every branch below builds every packet it needs in memory *before*
 * ever calling NF_DROP on the original — if any required piece can't
 * be built, the function returns 0 before dropping anything, exactly
 * the invariant the original SPLIT-only version of this function
 * established. A best-effort piece (a FAKE decoy layered onto SPLIT/
 * DISORDER) that fails to build is logged and skipped rather than
 * aborting the whole chain — see build_decoy(). */
static int	try_apply_chain(t_engine_ctx *ctx, struct nfq_q_handle *qh,
	uint32_t id, const uint8_t *raw, size_t raw_len, const t_tcp_view *tcp,
	const t_strategy_chain *chain)
{
	ssize_t				split_offset;
	uint8_t				seg1[65536];
	uint8_t				seg2[65536];
	size_t				seg1_len;
	size_t				seg2_len;
	uint8_t				decoy[65536];
	size_t				decoy_len;
	int					have_decoy;
	t_strategy			primary;

	primary = chain->actions[0];

	/* Pure FAKE never drops or rebuilds the real packet at all — it
	 * only injects a decoy alongside it, so the real packet's own
	 * fate is untouched (caller's default ACCEPT handles it). */
	if (chain->action_count == 1 && primary == STRATEGY_FAKE)
	{
		build_decoy(ctx, raw, raw_len, decoy, &decoy_len, &have_decoy);
		if (have_decoy && inject_or_log(ctx, "fake", decoy, decoy_len))
			ctx->stats.fake_decoys_sent++;
		return (0);
	}

	split_offset = tls_find_sni_split(tcp->payload, tcp->payload_len);
	if (split_offset <= 0 || (size_t)split_offset >= tcp->payload_len)
	{
		log_msg(ctx, LOG_DEBUG,
			"[chain] no usable split offset, falling back to accept\n");
		return (0);
	}

	if (chain->action_count == 1 && primary == STRATEGY_FRAGMENT)
	{
		if (packet_fragment_ipv4(raw, raw_len, (size_t)split_offset,
				seg1, &seg1_len, seg2, &seg2_len) != PACKET_OK)
		{
			log_msg(ctx, LOG_WARN, "[chain] packet_fragment_ipv4 failed, "
				"falling back to accept\n");
			return (0);
		}
		if (inject_or_log(ctx, "fragment1", seg1, seg1_len)
			&& inject_or_log(ctx, "fragment2", seg2, seg2_len))
			ctx->stats.packets_fragment++;
		nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		return (1);
	}

	/* Every remaining supported chain needs the two TCP-level
	 * segments (SPLIT and DISORDER both build them; FAKE+SPLIT/
	 * SPLIT+FAKE need them too, plus a decoy). */
	if (packet_split_tcp_v4(raw, raw_len, (size_t)split_offset,
			seg1, &seg1_len, seg2, &seg2_len) != PACKET_OK)
	{
		log_msg(ctx, LOG_WARN, "[chain] packet_split_tcp_v4 failed, "
			"falling back to accept\n");
		return (0);
	}

	if (chain->action_count == 1 && primary == STRATEGY_SPLIT)
	{
		if (inject_or_log(ctx, "split1", seg1, seg1_len)
			&& inject_or_log(ctx, "split2", seg2, seg2_len))
			ctx->stats.packets_split++;
	}
	else if (chain->action_count == 1 && primary == STRATEGY_DISORDER)
	{
		/* Reversed transmission order — TCP's own reassembly at the
		 * destination handles genuine out-of-order arrival by design. */
		if (inject_or_log(ctx, "disorder2", seg2, seg2_len)
			&& inject_or_log(ctx, "disorder1", seg1, seg1_len))
			ctx->stats.packets_disorder++;
	}
	else if (chain->action_count == 2 && primary == STRATEGY_FAKE
		&& chain->actions[1] == STRATEGY_SPLIT)
	{
		/* Decoy leads, built from the original (pre-split) packet. */
		build_decoy(ctx, raw, raw_len, decoy, &decoy_len, &have_decoy);
		if (have_decoy)
			inject_or_log(ctx, "fake", decoy, decoy_len);
		if (inject_or_log(ctx, "split1", seg1, seg1_len)
			&& inject_or_log(ctx, "split2", seg2, seg2_len))
			ctx->stats.packets_split++;
		if (have_decoy)
			ctx->stats.fake_decoys_sent++;
	}
	else if (chain->action_count == 2 && primary == STRATEGY_SPLIT
		&& chain->actions[1] == STRATEGY_FAKE)
	{
		/* Decoy interleaved between the two real segments, built
		 * from seg2 so it shares seg2's starting sequence number —
		 * it can never actually collide with the real seg2 that
		 * follows immediately after, since the decoy's checksum is
		 * invalid and its TTL is limited. */
		build_decoy(ctx, seg2, seg2_len, decoy, &decoy_len, &have_decoy);
		inject_or_log(ctx, "split1", seg1, seg1_len);
		if (have_decoy)
			inject_or_log(ctx, "fake", decoy, decoy_len);
		if (inject_or_log(ctx, "split2", seg2, seg2_len))
			ctx->stats.packets_split++;
		if (have_decoy)
			ctx->stats.fake_decoys_sent++;
	}
	else
	{
		/* Not a chain shape this function knows how to execute —
		 * should be unreachable given strategy_chain_is_safe(), but
		 * fail open rather than drop anything if it ever happens. */
		log_msg(ctx, LOG_WARN, "[chain] unrecognized chain shape, "
			"falling back to accept\n");
		return (0);
	}

	nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	return (1);
}

static int	packet_callback(struct nfq_q_handle *qh,
	struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	t_engine_ctx					*ctx;
	struct nfqnl_msg_packet_hdr	*ph;
	unsigned char					*raw;
	int								raw_len;
	uint32_t						id;
	t_ipv4_view						ip4;
	t_ipv6_view						ip6;
	t_tcp_view						tcp;
	t_flow_key						key;
	t_flow_entry					*flow;
	time_t							now;
	char							host[256];
	t_flow_class					classified;
	t_strategy						strat;
	t_strategy_chain				chain;
	int								is_v4;
	size_t							flow_count_before;
	int								ip_status;

	(void)nfmsg;
	ctx = data;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;
	raw_len = nfq_get_payload(nfa, &raw);
	now = time(NULL);
	host[0] = '\0';
	classified = FLOW_UNCLASSIFIED;
	strat = STRATEGY_PASS;
	chain.action_count = 1;
	chain.actions[0] = STRATEGY_PASS;
	is_v4 = 0;
	ctx->stats.packets_seen++;

	if (raw_len < 1)
	{
		log_msg(ctx, LOG_DEBUG, "[pkt id=%u] empty payload, accept\n", id);
		ctx->stats.packets_passed++;
		return (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL));
	}

	if ((raw[0] >> 4) == 4)
		ip_status = packet_parse_ipv4(raw, (size_t)raw_len, &ip4);
	else if ((raw[0] >> 4) == 6)
		ip_status = packet_parse_ipv6(raw, (size_t)raw_len, &ip6);
	else
		ip_status = PACKET_ERR_UNSUPPORTED;

	if (ip_status != PACKET_OK)
	{
		if (ip_status == PACKET_ERR_UNSUPPORTED)
			ctx->stats.unsupported_packets++;
		else
			ctx->stats.parse_failures++;
		log_msg(ctx, LOG_DEBUG, "[pkt id=%u] ip parse status=%d, "
			"accept\n", id, ip_status);
		ctx->stats.packets_passed++;
		return (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL));
	}

	if ((raw[0] >> 4) == 4 && ip4.protocol == 6
		&& packet_parse_tcp(ip4.payload, ip4.payload_len, &tcp) == PACKET_OK)
	{
		is_v4 = 1;
		build_flow_key_v4(&ip4, &tcp, &key);
		flow_count_before = ctx->flows.live_count;
		flow = flow_lookup_or_create(&ctx->flows, &key, now);
		if (ctx->flows.live_count != flow_count_before)
			ctx->stats.flows_created++;
		else if ((tcp.flags & TCP_FLAG_SYN) && !(tcp.flags & TCP_FLAG_ACK))
			flow_restart(flow, now);
		if (flow_seq_is_next(flow, tcp.seq, tcp.payload_len))
			classified = classify(flow, tcp.payload, tcp.payload_len,
					host, sizeof(host));
		else
			log_msg(ctx, LOG_DEBUG, "[flow] out-of-order/duplicate "
				"segment (seq=%u expected=%u), not appended\n",
				tcp.seq, flow->next_seq);
		if (ctx->log_level >= LOG_DEBUG)
		{
			char	src_str[INET_ADDRSTRLEN];
			char	dst_str[INET_ADDRSTRLEN];

			inet_ntop(AF_INET, &ip4.header->src, src_str, sizeof(src_str));
			inet_ntop(AF_INET, &ip4.header->dst, dst_str, sizeof(dst_str));
			log_msg(ctx, LOG_DEBUG, "[pkt id=%u v4 %s:%u->%s:%u] ", id,
				src_str, ntohs(tcp.header->src_port), dst_str,
				ntohs(tcp.header->dst_port));
		}
	}
	else if ((raw[0] >> 4) == 6
		&& packet_parse_tcp(ip6.payload, ip6.payload_len, &tcp) == PACKET_OK)
	{
		build_flow_key_v6(&ip6, &tcp, &key);
		flow_count_before = ctx->flows.live_count;
		flow = flow_lookup_or_create(&ctx->flows, &key, now);
		if (ctx->flows.live_count != flow_count_before)
			ctx->stats.flows_created++;
		else if ((tcp.flags & TCP_FLAG_SYN) && !(tcp.flags & TCP_FLAG_ACK))
			flow_restart(flow, now);
		if (flow_seq_is_next(flow, tcp.seq, tcp.payload_len))
			classified = classify(flow, tcp.payload, tcp.payload_len,
					host, sizeof(host));
		else
			log_msg(ctx, LOG_DEBUG, "[flow] out-of-order/duplicate "
				"segment (seq=%u expected=%u), not appended\n",
				tcp.seq, flow->next_seq);
		log_msg(ctx, LOG_DEBUG, "[pkt id=%u v6 port %u->%u] ", id,
			ntohs(tcp.header->src_port), ntohs(tcp.header->dst_port));
	}
	else
	{
		/* IP layer parsed fine, but it's not TCP, or the TCP header
		 * itself is malformed/truncated — either way, not ours to
		 * touch. */
		log_msg(ctx, LOG_DEBUG, "[pkt id=%u] not TCP or TCP parse "
			"failed, accept\n", id);
		/* Short-circuit order matters: ip4 is only initialized when
		 * we came down the v4 path, so raw[0]>>4==4 must be checked
		 * first or ip4.protocol would be an uninitialized read. */
		if ((raw[0] >> 4) == 4 && ip4.protocol != 6)
			ctx->stats.unsupported_packets++;
		else
			ctx->stats.parse_failures++;
		ctx->stats.packets_passed++;
		return (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL));
	}

	if (host[0] != '\0')
	{
		/* This is necessarily the flow's classifying packet (classify()
		 * only fills `host` on the call that completes classification),
		 * so this is the one and only time strategy_chain_for_domain()
		 * needs to run for this flow — cache it for every later packet. */
		t_strategy_source	source;
		char				chain_desc[64];

		source = strategy_resolve_chain(&ctx->strategies, &ctx->discovered,
				ctx->fingerprint, (int64_t)now, host, &chain, NULL);
		strat = chain.actions[0];
		flow->strategy = (int)strat;
		flow->chain = chain;
		flow->strategy_decided = 1;
		strategy_chain_describe(&chain, chain_desc, sizeof(chain_desc));
		log_msg(ctx, LOG_INFO, "[flow] classified host=%s strategy=%s "
			"source=%s\n", host, chain_desc, strategy_source_name(source));
	}
	else if (flow->strategy_decided)
	{
		strat = (t_strategy)flow->strategy;
		chain = flow->chain;
	}

	log_msg(ctx, LOG_DEBUG, "host=%s strategy=%s ", host[0] ? host : "(none)",
		strategy_name(strat));

	ctx->stats.flows_expired += flow_evict_expired(&ctx->flows, now,
			FLOW_DEFAULT_TIMEOUT_SECONDS);

	/* Only the flow's classifying packet — the one whose bytes just
	 * completed the ClientHello — is eligible for a live chain action;
	 * every other packet (including ones that only contributed to an
	 * earlier truncated attempt) falls through to plain ACCEPT below.
	 * IPv6 is not wired to any wire-modifying strategy in this pass —
	 * see README/docs/packet-mode.md. */
	if (is_v4 && classified == FLOW_TLS && strat != STRATEGY_PASS
		&& flow->reasm_len == tcp.payload_len)
	{
		if (try_apply_chain(ctx, qh, id, raw, (size_t)raw_len, &tcp, &chain))
		{
			log_msg(ctx, LOG_DEBUG, "verdict=drop+chain\n");
			return (0);
		}
	}

	ctx->stats.packets_passed++;
	log_msg(ctx, LOG_DEBUG, "verdict=accept\n");
	return (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL));
}

/* Optional: DPI_PROXY_STRATEGY_CONF (default "strategy.conf" in the
 * cwd). A missing file is not an error — the config stays
 * default-PASS, which is the safe starting point. Bounded read
 * (8KB), reuses the already unit-tested strategy_config_parse(). */
static void	load_strategy_config(t_engine_ctx *ctx)
{
	const char	*path;
	FILE		*f;
	char		buf[8192];
	size_t		n;
	size_t		skipped;

	path = getenv("DPI_PROXY_STRATEGY_CONF");
	if (path == NULL)
		path = "strategy.conf";

	f = fopen(path, "r");
	if (f == NULL)
	{
		log_msg(ctx, LOG_INFO, "[strategy] no config at %s, all traffic "
			"defaults to PASS\n", path);
		return ;
	}

	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	skipped = strategy_config_parse(&ctx->strategies, buf, n);
	if (skipped > 0)
		log_msg(ctx, LOG_WARN, "[strategy] %zu line(s) in %s were "
			"skipped as malformed (see messages above)\n", skipped, path);
	log_msg(ctx, LOG_INFO, "[strategy] loaded %s: default=%s, %zu "
		"domain rule(s)\n", path, strategy_name(ctx->strategies
			.default_strategy), ctx->strategies.rule_count);
}

/* Optional: DPI_PROXY_DISCOVERY_CACHE (default "discovery-cache.conf"
 * in the cwd — the same default and env var --probe writes to, see
 * main_packet.c). A missing file just means no auto-discovered
 * strategies yet. Also (re)computes the network fingerprint the
 * cache entries are matched against. */
static void	load_discovery_cache(t_engine_ctx *ctx)
{
	const char	*path;
	size_t		i;
	size_t		fresh;

	path = getenv("DPI_PROXY_DISCOVERY_CACHE");
	if (path == NULL)
		path = "discovery-cache.conf";
	if (discovery_cache_load_file(&ctx->discovered, path) < 0)
		log_msg(ctx, LOG_WARN, "[discovery] could not read %s, ignoring "
			"auto-discovered strategies\n", path);
	ctx->fingerprint = netfingerprint_current();
	ctx->fingerprint_checked_at = (int64_t)time(NULL);
	fresh = 0;
	i = 0;
	while (i < ctx->discovered.count)
	{
		if (discovery_cache_lookup(&ctx->discovered,
				ctx->discovered.entries[i].domain, ctx->fingerprint,
				DISCOVERY_CACHE_DEFAULT_TTL_SECONDS,
				ctx->fingerprint_checked_at) != NULL)
			fresh++;
		i++;
	}
	log_msg(ctx, LOG_INFO, "[discovery] loaded %s: %zu entr%s, %zu fresh "
		"for network profile %016llx\n", path, ctx->discovered.count,
		ctx->discovered.count == 1 ? "y" : "ies", fresh,
		(unsigned long long)ctx->fingerprint);
}

/* If the engine started before the network was up (no default route →
 * NETFP_UNKNOWN, which never matches any cache entry), keep retrying
 * cheaply instead of ignoring the cache until the next restart. */
#define FINGERPRINT_RETRY_SECONDS 30

static void	maybe_refresh_unknown_fingerprint(t_engine_ctx *ctx)
{
	int64_t	now;

	if (ctx->fingerprint != NETFP_UNKNOWN)
		return ;
	now = (int64_t)time(NULL);
	if (now - ctx->fingerprint_checked_at < FINGERPRINT_RETRY_SECONDS)
		return ;
	ctx->fingerprint = netfingerprint_current();
	ctx->fingerprint_checked_at = now;
	if (ctx->fingerprint != NETFP_UNKNOWN)
		log_msg(ctx, LOG_INFO, "[discovery] network came up, profile "
			"%016llx\n", (unsigned long long)ctx->fingerprint);
}

/* SIGHUP: re-read strategy.conf and the discovery cache (and the
 * network fingerprint) without restarting, then drop every flow's
 * cached decision so nothing keeps using a choice made against the
 * old config. */
static void	reload_strategies(t_engine_ctx *ctx)
{
	size_t	cleared;

	strategy_config_init(&ctx->strategies);
	load_strategy_config(ctx);
	load_discovery_cache(ctx);
	cleared = flow_invalidate_decisions(&ctx->flows);
	log_msg(ctx, LOG_INFO, "[reload] strategies reloaded, %zu cached flow "
		"decision(s) invalidated\n", cleared);
}

int	nfqueue_engine_run(int queue_num)
{
	struct nfq_handle	*h;
	struct nfq_q_handle	*qh;
	t_engine_ctx		*ctx;
	char				buf[65536] __attribute__((aligned));
	int					fd;
	ssize_t				received;
	int					rc;
	struct sigaction	sa;

	/* t_engine_ctx embeds a t_flow_table (FLOW_TABLE_MAX entries x a
	 * FLOW_REASSEMBLY_CAP buffer each, ~67MB) — heap-allocated
	 * deliberately, a stack-local of that size reliably segfaults
	 * against the default ~8MB stack (caught by test_flow.c doing
	 * exactly that before this was fixed). */
	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
	{
		fprintf(stderr, "calloc failed\n");
		return (-1);
	}
	flow_table_init(&ctx->flows);
	strategy_config_init(&ctx->strategies);
	ctx->log_level = log_level_from_env();
	load_strategy_config(ctx);
	load_discovery_cache(ctx);
	ctx->raw_v4_fd = -1;

	log_msg(ctx, LOG_INFO, "[startup] dpi-proxy packet mode starting, "
		"queue=%d\n", queue_num);

	if (nft_rules_apply(queue_num) != 0)
	{
		fprintf(stderr, "nft_rules_apply failed (need root/"
			"CAP_NET_ADMIN, and nftables installed)\n");
		free(ctx);
		return (-1);
	}
	log_msg(ctx, LOG_INFO, "[startup] nftables rules applied "
		"(table inet %s)\n", NFT_TABLE_NAME);

	h = nfq_open();
	if (h == NULL)
	{
		fprintf(stderr, "nfq_open failed\n");
		nft_rules_remove();
		free(ctx);
		return (-1);
	}

	/* Deliberately NOT calling nfq_unbind_pf()/nfq_bind_pf(): those
	 * are a legacy ip_queue-era step that affects the whole protocol
	 * family process-wide, which risks disrupting any *other*
	 * NFQUEUE consumer on the system — the nftables `queue` statement
	 * (see nft_rules.c) is what actually routes packets to us, and
	 * doesn't need it. */
	qh = nfq_create_queue(h, (uint16_t)queue_num, packet_callback, ctx);
	if (qh == NULL)
	{
		fprintf(stderr, "nfq_create_queue failed\n");
		nfq_close(h);
		nft_rules_remove();
		free(ctx);
		return (-1);
	}

	nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

	/* sigaction with no SA_RESTART: recv() below must return EINTR on
	 * SIGINT/SIGTERM so the loop can check g_stop, not silently
	 * resume — plain signal()'s restart behavior is unspecified
	 * enough not to rely on for that. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	log_msg(ctx, LOG_INFO, "[startup] queue active, entering receive "
		"loop\n");

	fd = nfq_fd(h);
	rc = 0;
	while (!g_stop)
	{
		if (g_reload)
		{
			g_reload = 0;
			reload_strategies(ctx);
		}
		maybe_refresh_unknown_fingerprint(ctx);
		received = recv(fd, buf, sizeof(buf), 0);
		if (received < 0)
		{
			if (errno == EINTR)
				continue ;
			perror("recv");
			rc = -1;
			break ;
		}
		nfq_handle_packet(h, buf, (int)received);
	}

	log_msg(ctx, LOG_INFO, "[shutdown] signal received, cleaning up\n");
	log_stats(ctx);

	nfq_destroy_queue(qh);
	nfq_close(h);
	nft_rules_remove();
	if (ctx->raw_v4_fd >= 0)
		close(ctx->raw_v4_fd);
	log_msg(ctx, LOG_INFO, "[shutdown] nftables rules removed, exiting\n");
	free(ctx);

	return (rc);
}

#endif /* HAVE_NFQUEUE_ENGINE */
