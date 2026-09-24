# Network profiles (packet mode)

Packet mode only (Linux). Builds on [docs/discovery.md](discovery.md)'s
per-network cache scoping: the discovery cache is scoped by a network
fingerprint. This page describes what that fingerprint is computed
from and the ways to actually *see* it.

## What's in a network profile

`netprofile_gather()` (`include/netfingerprint.h`,
`src/discovery/netfingerprint.c`) reads, purely from local state:

- **interface** and **link type** (wired/Wi-Fi/other) — from
  `/proc/net/route` and `/sys/class/net/<iface>/wireless`.
- **SSID**, only when on Wi-Fi — from a local `nmcli` query (talks to
  NetworkManager over the local D-Bus; fork+execvp with a fixed argv,
  never a shell).
- **IPv4/IPv6 default-route availability** — from `/proc/net/route`
  and `/proc/net/ipv6_route`.
- **this host's own local address** on that interface — via
  `ioctl(SIOCGIFADDR)` on a throwaway local socket; no packet is ever
  sent to determine it.

All of the above feed `netfingerprint_current()`'s hash, which is what
actually scopes the discovery cache (switching networks — new Wi-Fi, Ethernet vs. Wi-Fi, a VPN taking the
default route — changes the fingerprint, which makes every cached
result for the old network a miss until re-probed).

## No telemetry, ever

Every signal above is read locally. **Nothing is ever sent to any
external service to compute any of it.** In particular:

- There is no "what's my public IP" lookup against a third-party echo
  service. `local_addr` is this host's own interface address as the
  kernel already knows it — behind NAT, that's a private address, not
  an internet-facing one, and that's deliberate.
- There is no ASN/country/GeoIP lookup. Doing that honestly would
  require either calling an external lookup service (an external
  dependency and, arguably, telemetry-adjacent — the antithesis of
  "everything remains local") or bundling an offline GeoIP database
  (real disk/maintenance cost this project doesn't take on). Rather
  than fake it or half-implement it, this is explicitly **not
  implemented** — the "ISP/ASN labels may be displayed descriptively
  if detected" language in this project's design goals is
  conditional ("if detected") precisely to allow this: nothing here
  hard-codes or infers an ISP/ASN, and no logic anywhere branches on
  one.

## Seeing your current profile

```sh
dpi-proxy-packet --status
```

Prints, in one place: the current network (interface, link type,
SSID if applicable, IPv4/IPv6 availability, local address), the
current profile fingerprint, every manual override from
`strategy.conf`, and every auto-discovered strategy that's actually
fresh (matching fingerprint, within TTL) for the network you're on
right now. Read-only — no privilege needed, no network I/O beyond the
local queries above.

## Export / import

```sh
dpi-proxy-packet --export-profile my-strategies.conf
dpi-proxy-packet --import-profile my-strategies.conf
```

The discovery cache is already a portable, human-readable text file
(see [docs/discovery.md](discovery.md)'s cache format); these two
flags just make moving it between machines explicit and safe:
`--export-profile` re-serializes and validates the current cache to a
path you choose, `--import-profile` merges another file's entries
into the current cache (last-write-wins per domain, same as every
other config format in this project) and saves the result.

**A network's fingerprint is specific to the machine that computed
it** (interface names, in particular, commonly differ between
machines even on the same physical network) — an imported entry only
actually applies once its fingerprint happens to match the importing
machine's current network. `--status` after an import shows you
exactly what's live.

## Validation status

`netprofile_gather()`'s every field (interface, link type, SSID,
IPv4/IPv6 availability, local address) was cross-checked against real
`ip route`/`nmcli` output and matched exactly; `--status`, `--export-profile`, and
`--import-profile` were all run live and behaved correctly, including
a real probe → cache → export → import-to-a-different-cache-file round
trip.
