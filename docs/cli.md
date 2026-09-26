# dpictl — command reference

`dpictl` is the control CLI for dpi-proxy's transparent-mode service,
identical across Linux, Windows and macOS (`dpictl` on Linux/macOS is
a bash/sh script; on Windows, `dpictl.cmd` runs the equivalent
PowerShell). `dpi-proxy-ctl` is kept as a compatibility alias — every
command below works the same way through either name; scripts written
against `dpi-proxy-ctl` keep working unchanged.

Commands that change service state (`start`/`stop`/`restart`/`reload`)
need root (`sudo`) on Linux/macOS or an elevated/Administrator terminal
on Windows. Everything else works as a normal user.

## status

```
dpictl status              # short summary
dpictl status --verbose    # full internals (engine, DNS, flows, PF/nft state, ...)
```

The default output is meant to be read at a glance:

```
dpi-for-everyone 2.0.0
Service: Running
Protection: Active
DNS: Healthy
Mode: Transparent
Bypassed: 123
Failures: 0
```

`--verbose` prints the same fields the pre-2.0 default output had:
engine state, DNS resolver/interception detail, network fingerprint,
flow counters, learned-decision counts, and (as root) live nftables/PF
rule counts.

## start / stop / restart / reload

Start, stop, restart the service, or reload manual rules from
`strategy.conf` without restarting (`reload` sends the daemon SIGHUP).
`stop` always leaves the machine on ordinary, unbypassed networking —
this is the manual equivalent of fail-open.

## logs [N]

The last N lines (default 100) of the service's log.

## strategy DOMAIN

What applies to DOMAIN right now: a manual rule from `strategy.conf`,
else a learned decision for the current network, else "automatic"
(nothing learned yet — the ladder decides per-connection).

## diagnose DOMAIN

A read-only snapshot for one domain: system DNS answer, the strategy
that applies, and a live HTTPS check (status code, certificate
verification result). Not needed for normal use — for when something
looks wrong with one specific site.

## doctor

Read-only health checks, each printed as `[PASS|WARN|FAIL]` with a
one-line reason. Exits 0 if nothing failed, 1 otherwise. Never modifies
or disables anything it finds — including other DPI tools.

Checks: permissions (root/Administrator, binary present), service
state, interception layer (nftables table / PF anchor / WinDivert
driver), DNS-over-HTTPS health, internet reachability, that the binary
actually supports transparent mode, other known DPI-bypass tools
(dpi-bypass, GoodbyeDPI, zapret and its `nfqws`/`winws` processes,
SpoofDPI, ByeDPI, tpws, ciadpi) or a VPN/tunnel interface that might
also be filtering HTTPS, and stale interception rules left behind
while the service is stopped.

`doctor` never stops, disables, or reconfigures another program it
detects — it only reports what it finds so you can decide.

## support-bundle [FILE]

Writes a local diagnostics archive (`.tar.gz` on Linux/macOS, `.zip`
on Windows) containing: version, OS/architecture, `status --verbose`
output, `doctor` output, recent service logs, `strategy.conf`, and
service state.

**No telemetry**: this command only ever writes a local file; nothing
is sent anywhere by dpictl itself. Redacted before writing: anything
that looks like a token/key/secret/password, `$HOME`/`%USERPROFILE%`,
your username, and the per-domain/per-IP DNS decision history (only a
count is included, never the raw domain/IP list — that is effectively
your browsing history). Review the archive yourself before sharing it
with anyone; it can still contain domain names you visited and log
timestamps.

## version

Prints the installed `dpi-proxy` version and exits.

## Packet mode (Linux, optional, advanced)

`dpictl packet <start|stop|restart|reload|status|logs>`,
`dpictl probe DOMAIN`, `dpictl reprobe DOMAIN`, `dpictl networks` — see
[packet-mode.md](packet-mode.md). Most installs never need these;
transparent mode is the default, automatic engine.
