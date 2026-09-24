# Packet mode (Linux) — reference

This covers running `dpi-proxy-packet` manually, its strategy config
format in detail, and how to test it yourself. For the recommended
install path (systemd service via `scripts/install.sh`), see the main
[README](../README.md) — this document is for manual/advanced use, and
for anyone extending it.

Packet mode is a second, more invasive architecture alongside the
portable SOCKS5 proxy: transparent, system-wide packet interception on
Linux via **nftables + NFQUEUE**, in the same architectural class as
tools like GoodbyeDPI/zapret — no browser SOCKS configuration needed.
It classifies outbound TCP/80 and TCP/443 traffic by HTTP Host / TLS
SNI and applies a strategy per domain. See
[docs/architecture.md](architecture.md) for how it works internally.
Packet mode is optional; the recommended Linux engine is transparent
mode ([docs/transparent-mode.md](transparent-mode.md)).

## Running it manually

```sh
sudo apt-get install -y libnetfilter-queue-dev nftables
make packet-mode
sudo ./dpi-proxy-packet --capabilities   # confirm real CAP_NET_ADMIN/CAP_NET_RAW
DPI_PROXY_LOG_LEVEL=debug sudo ./dpi-proxy-packet
```

Least-privilege alternative to running the whole thing under `sudo`:

```sh
sudo setcap cap_net_admin,cap_net_raw+eip ./dpi-proxy-packet
getcap ./dpi-proxy-packet   # must print "cap_net_admin,cap_net_raw=eip" — if
                            # it prints nothing, setcap silently didn't apply
                            # (e.g. filesystem mounted noexec/nosuid, or the
                            # calling shell itself lacks CAP_SETFCAP); fall
                            # back to running the whole thing under sudo
./dpi-proxy-packet
```

(The installed systemd service takes a different, more thorough
approach to the same idea — a restricted `CapabilityBoundingSet`
rather than file capabilities on the binary — see
[docs/architecture.md](architecture.md#privilege-model-system-service).)

`DPI_PROXY_LOG_LEVEL` (`error|warn|info|debug`, or the legacy
`DPI_PROXY_DEBUG=1` for `debug`) controls verbosity. Debug output logs
one bounded line per packet: id, family, src/dst ip:port, detected
Host/SNI (or `(none)`), selected strategy, and the verdict — never
payload bytes.

Manual recovery if something looks stuck: `sudo nft delete table inet
dpi_proxy`. The nftables rule uses the `bypass` flag, so if the daemon
isn't running or crashes, matched traffic falls back to normal
`ACCEPT` instead of being silently dropped.

## Strategy config

Default path `./strategy.conf` (or `/etc/dpi-proxy/strategy.conf` when
installed via `scripts/install.sh`), override with
`DPI_PROXY_STRATEGY_CONF=/path/to/file`. A missing file just means
everything defaults to `pass`. Comments (`#` or `;`) and blank lines
are ignored; malformed lines are skipped individually (never abort the
whole file) with a `[strategy] line N: ...` warning.

```ini
# lines outside [domains] set the global default
default = pass
fake_ttl = 8              # optional; IP TTL used on FAKE decoy packets (1-255, default 8)

[domains]
example.com = pass        # exact match
.example.com = split      # leading dot: matches example.com AND any subdomain
discord.com = fake+split  # chain: two actions, executed in order
```

Exact-domain rules are checked before suffix (`.`-prefixed) rules. A
domain repeated later in the file overwrites its earlier rule
(deterministic last-write-wins), not a duplicate entry.

### Strategies

All strategies below are IPv4-only in this version, and (same as
SPLIT always was) only take effect on a flow's classifying TLS
packet — the one whose bytes complete a *single-packet* ClientHello.
Everything else (IPv6, HTTP, multi-packet ClientHellos) is
classification-only/PASS. See
[docs/architecture.md](architecture.md#strategy-engine-and-chains) for
the packet-construction detail. PASS and SPLIT are verified on real
traffic; the others so far only under unit tests/sanitizers.

- `pass` — accept unmodified.
- `split` — re-segments the TCP payload into two independent, wire-
  valid TCP segments, split mid-SNI-hostname.
- `disorder` — same split as above, but the two segments are
  transmitted in reversed order (second segment first). Real TCP
  reassembly at the destination handles genuine out-of-order arrival
  correctly by design; a DPI box doing simple linear/sequential
  inspection may not.
- `fake` — injects one synthetic decoy segment at the real data's
  starting sequence number: same 5-tuple/seq/ack/flags as the real
  packet, IP TTL lowered to `fake_ttl`, and its TCP checksum
  deliberately made invalid (so a real endpoint's TCP stack drops it
  before it can ever touch application/stream state — independent of
  network path). The real packet is passed through completely
  unmodified alongside it; nothing about the real stream is touched.
  Heuristic effectiveness — depends on the DPI in question; not a
  guarantee.
- `fragment` — **true IP-layer fragmentation (RFC 791)**, explicitly
  *not* TCP segmentation (that's what `split`/`disorder` do). Splits
  one already-complete, already-checksummed IPv4 datagram into two IP
  fragments (correct fragment-offset field, MF flag, shared IP ID).
  Only the first fragment carries the TCP header; the second is a
  headerless continuation. The destination's IP stack reassembles
  before TCP ever sees it, so a DPI box that doesn't do IP
  reassembly never sees a complete record. Because the original
  datagram is complete before being fragmented, its TCP checksum is
  never recomputed — it's simply still valid once reassembled.

### Chains

A domain's config value may be a single strategy name above, or one
of these three `+`-joined chains (the only combinations judged safe
to implement; every other combination is rejected at parse time):

- `fake+split` — decoy leads, then the real data goes out as two
  split segments.
- `split+fake` — the real data goes out as two split segments with a
  decoy interleaved between them, built to share the second
  segment's starting sequence number (so it reads, to a shallow
  inspector, like it could be that segment — but its invalid checksum
  means it can never actually compete with the real one that follows).
- `split+disorder` — accepted for config compatibility, but executed
  identically to plain `disorder`: DISORDER's only correct
  construction already *is* "split, then reorder", so this specific
  combination has no distinct safe meaning beyond that.

Any other combination (e.g. `fake+disorder`, anything involving
`fragment`) is rejected at config-parse time as an unsupported/unsafe
combination — same fail-safe posture as an unrecognized strategy name
(the line is skipped with a `[strategy] line N: ...` warning, and the
domain falls through to whatever rule would otherwise apply).

### Fallback

Every chain step builds every packet it needs in memory *before* the
original is ever dropped — construction failure at any required step
aborts the whole chain, logs why at `warn`, and falls through to
plain `ACCEPT` of the untouched original. A best-effort piece (the
`fake` decoy layered onto a `split`) that fails to build is logged
and skipped rather than aborting the rest of the chain — the chain
degrades to the plain action it was layered onto instead.

## CLI reference

```
dpi-proxy-packet [--config PATH] [--discovery-cache PATH]
                  [--log-level error|warn|info|debug]
                  [--probe DOMAIN] [--reprobe DOMAIN]
                  [--show-strategy DOMAIN] [--status] [--json]
                  [--export-profile PATH] [--import-profile PATH]
                  [--capabilities] [--version] [--help]
```

`scripts/dpi-proxy-ctl` wraps the most common of these (plus
`systemctl`/`journalctl`) behind short subcommands —
`dpi-proxy-ctl status|start|stop|restart|probe|strategy|networks|logs`
— see the README's "Lightweight CLI control" section. Every flag below
keeps working directly regardless.

`--probe`/`--reprobe`/`--show-strategy` are the automatic strategy
discovery commands — see [docs/discovery.md](discovery.md) for the
full reference (candidate ladder, caching/revalidation rules, manual-
override precedence, safety bounds). `--status`/`--export-profile`/
`--import-profile` are the network-profile commands — see
[docs/network-profiles.md](network-profiles.md).

Prints an actionable message (not a bare error code) on common startup
failures: a malformed strategy config (with the offending line
number), missing `libnetfilter-queue-dev`, or missing `nft`/
capabilities.

## Testing it yourself (PASS)

In one terminal:
```sh
DPI_PROXY_DEBUG=1 sudo ./dpi-proxy-packet
```
In another:
```sh
curl -I http://example.com
curl -I https://example.com
sudo nft list table inet dpi_proxy   # shows the rule + its packet/byte counter
```
What to look for: the engine's debug log shows a line per packet for
both requests (`host=example.com strategy=pass verdict=accept`); both
`curl`s succeed exactly as they would with the engine off; the
`counter` in `nft list table inet dpi_proxy` has gone up. Stop the
engine with Ctrl-C (SIGINT) and confirm `sudo nft list tables` no
longer shows `inet dpi_proxy`.

## Testing it yourself (SPLIT)

```sh
echo -e "default = pass\n\n[domains]\nexample.com = split" > strategy.conf
DPI_PROXY_DEBUG=1 sudo ./dpi-proxy-packet &
sudo tcpdump -i any -w split.pcap 'tcp port 443 and host example.com'
# in another terminal:
curl -4 -I https://example.com
```
Expected debug log: `strategy=split` followed by `verdict=drop+chain`
(or, if the split couldn't be computed/injected, a fallback
`verdict=accept` — read the `[chain]` line above it for why). Open
`split.pcap` and check: the ClientHello arrives as two TCP segments
instead of one, the second segment's sequence number is exactly
`first_segment_seq + first_segment_len`, and there's no third copy of
either half (which would indicate the anti-loop mark isn't excluding
the injected packets and they're being re-queued). The same log/
capture approach works for `disorder`, `fake`, `fragment`, and the
chain values (`fake+split`, `split+fake`) — just change
`strategy.conf`'s value; see "Strategies" above for what to expect on
the wire for each.

Try `curl` against more than one TLS host before concluding the split
itself is broken — some servers/CDNs reject a split ClientHello
regardless of whether it was constructed correctly; see "Limitations"
in the README.

Or just run the automated version of this: `./scripts/field-test-linux.sh
[domain]` does both the PASS and SPLIT checks above (plus SIGINT/
SIGTERM cleanup and repeated start/stop) and reports PASS/FAIL/SKIP.

## No root at all, not even for `apt-get install`?

You can still get `make packet-mode` to *compile* (not run) without
any privilege, by fetching the packages without installing them:

```sh
mkdir /tmp/nfq_vendor && cd /tmp/nfq_vendor
apt-get download libnetfilter-queue-dev libnetfilter-queue1 \
	libnfnetlink-dev libnfnetlink0 libmnl-dev libmnl0
for f in *.deb; do dpkg -x "$f" extracted/; done
cc -Wall -Wextra -Werror -DHAVE_NFQUEUE_ENGINE -Iinclude \
	-I extracted/usr/include -c src/nfqueue/nfqueue_engine.c -o /tmp/e.o
```
This proves the code is correct against the real API; it does **not**
grant you the runtime privilege to actually bind a queue.

## IPv6

IPv4/IPv6 fixed headers and TCP are parsed and checksummed for both
families. IPv6 extension headers (hop-by-hop, routing, fragmentation,
...) are **not** walked — such packets are reported unsupported and
fail open (passed through unclassified, verdict still `ACCEPT`) rather
than risk misparsing a header chain this project doesn't fully
implement. SPLIT is IPv4-only by design (see
[docs/architecture.md](architecture.md)); IPv6 flows always fail open
to PASS.

## Security / design properties

- Never decrypts or MITMs TLS — SNI/Host classification only reads
  cleartext bytes already visible on the wire (the ClientHello's SNI
  extension, the HTTP Host header); the TLS handshake content itself
  is never touched.
- Never reads or acts on request bodies, cookies, or auth headers —
  classification stops at the Host/SNI value.
- Packet mode only ever affects traffic on the machine it runs on, to
  destinations that machine is already talking to — no remote relay,
  no traffic from other hosts.
- nftables state is isolated to a single dedicated `inet dpi_proxy`
  table; nothing else on the system's firewall is touched, and cleanup
  (SIGINT/SIGTERM, or manually via `sudo nft delete table inet
  dpi_proxy`) removes exactly that table.
- Fail-open throughout — see [docs/architecture.md](architecture.md#fail-open-behavior-summarized).
- No shell interpolation: nftables rules are applied via `fork`+
  `execvp` with a fixed argv, never `system()`/`popen()` with a built
  string.
