# Automatic strategy discovery (packet mode)

Packet mode only (Linux). Lets `dpi-proxy-packet` figure out which
strategy actually works for a domain instead of you guessing at
`strategy.conf` values by hand. See
[docs/architecture.md](architecture.md) for the packet engine this
builds on. (Transparent mode, the recommended Linux engine, has its
own automatic per-host learning and needs none of this — see
[docs/transparent-mode.md](transparent-mode.md).)

## The ladder

A fixed, ordered, non-configurable list of candidates, from least to
most invasive — deliberately curated, never a brute-force search of
every possible combination:

```
pass → split → fake → disorder → fragment → fake+split → split+fake
```

A discovery run walks this list and stops at the **first** candidate
that actually works — "pick the simplest working strategy" is
satisfied by construction: if `split` works, `fake`/`disorder`/
`fragment`/the chains are never even tried.

## Commands

```sh
dpi-proxy-packet --show-strategy DOMAIN   # read-only, no privilege needed
dpi-proxy-packet --probe DOMAIN           # auto-discover (skips if cache is fresh)
dpi-proxy-packet --reprobe DOMAIN         # like --probe, but always re-runs
```

`--show-strategy` never touches the network or nftables — it only
reads `strategy.conf` and the discovery cache and reports which one
would apply right now and why (`manual`, `auto-discovery`, or
`default`).

`--probe`/`--reprobe` need the same `CAP_NET_ADMIN`/`CAP_NET_RAW` as
running the engine itself (see `--capabilities`), because validating a
candidate means actually applying it to a real, temporary,
single-domain packet-mode session and performing one real TLS
connectivity check against it.

## Manual override always wins

If `strategy.conf` has an explicit rule (exact or suffix) for a
domain, `--probe`/`--reprobe` refuse to run and `--show-strategy`
reports the manual value — auto-discovery never second-guesses a rule
you wrote yourself. Remove the rule from `strategy.conf` first if you
want discovery to choose instead.

## How the running engine uses it

The packet engine resolves every newly classified flow with the same
precedence `--show-strategy` reports: manual `strategy.conf` rule →
fresh same-network cache entry → `default`. The `[flow] classified`
log line says which one applied (`source=manual|auto-discovery|
default`). The engine loads the cache at startup and re-reads both
files on `SIGHUP` (`systemctl reload dpi-proxy-packet`, or
`dpi-proxy-ctl reload`). `dpi-proxy-ctl probe`/`reprobe` stop the
service while probing (the probe's scoped engine uses the same
nftables table and queue, and would otherwise delete the service's
table) and start it again afterwards, which loads the new result.

A probe only counts a candidate as working if `openssl s_client`
completes a handshake **and** the certificate verifies for the domain
(`Verify return code: 0 (ok)`). An ISP block page that answers with
its own certificate is a failure, not a success. Note that no
packet-level strategy helps if DNS itself is poisoned (the connection
goes to the wrong server): check `getent hosts DOMAIN` against a
public resolver first. A reload also drops every
live flow's cached decision, and a new connection that reuses an old
4-tuple (a fresh SYN) is always re-classified, so no flow keeps a
stale `pass`. Connections whose ClientHello was already sent before
the reload keep their fate; the next connection picks up the new
strategy.

## Caching and revalidation

Results are cached in `discovery-cache.conf` (default path: the
current working directory, same as `strategy.conf`; override with
`DPI_PROXY_DISCOVERY_CACHE` or `--discovery-cache PATH`). The systemd
service uses `/etc/dpi-proxy/discovery-cache.conf`, and
`dpi-proxy-ctl` always passes the service's own paths, so prefer
`sudo dpi-proxy-ctl probe DOMAIN` over calling the binary from an
arbitrary directory. Entries are keyed by domain **and** a network
fingerprint — see [docs/network-profiles.md](network-profiles.md) for
exactly what feeds it (interface, link type, SSID, IPv4/IPv6
availability). A cached result is only reused when:

- the domain matches,
- the fingerprint matches the network you're on **right now** (a
  different network — different Wi-Fi, Ethernet vs. Wi-Fi, a VPN
  taking over the default route — never reuses another network's
  answer), and
- it's younger than `DISCOVERY_CACHE_DEFAULT_TTL_SECONDS` (24h).

Any other case is a cache miss, which `--probe` treats as "run a new
discovery"; `--reprobe` skips the freshness check entirely and always
re-runs. **Only a successful discovery is ever written to the cache**
— a run that found nothing working is reported but not persisted, so
it doesn't need separate expiry handling; the next `--probe` just
starts fresh.

## Safety bounds

- Each candidate gets at most `DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE`
  (2) attempts before moving on — except a local error (the probe
  itself couldn't run, e.g. nftables setup failed), which moves on
  immediately rather than burning retries on something that never
  actually tested anything.
- A whole discovery run is hard-bounded at
  `ladder length × max attempts` = 14 probe attempts, total, ever —
  see `discovery_run()` in `src/discovery/ladder.c`.
- Discovery is **only ever CLI-triggered** (`--probe`/`--reprobe`) —
  there is no background loop that re-runs it on its own, which is
  what keeps "avoid hammering hosts" and "never loop forever" true by
  construction rather than by policy alone.
- Every probe's temporary nftables state is removed on completion, on
  timeout, and defensively again as a final best-effort step
  regardless of how the probe ended — same "never leave stale
  nftables state" discipline as the main engine and
  `scripts/uninstall.sh`.

## Validation status

The full orchestration pipeline (temp config → scoped engine → real
`openssl s_client` connectivity check → cleanup → cache write/read)
has been exercised end-to-end for the `pass` candidate. The
`split`/`fake`/`disorder`/`fragment`/chain candidates have not yet
been live-validated through this pipeline against real DPI; treat
their results accordingly.
