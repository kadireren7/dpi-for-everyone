# Transparent mode (Linux, Windows, macOS)

`dpi-proxy --mode transparent`, run by the `dpi-proxy-transparent`
systemd service on Linux, the `dpi-proxy` service on Windows and the
`io.github.kadireren7.dpi-proxy` launchd daemon on macOS. It is
the recommended way to use dpi-for-everyone: after installing, every
application's HTTPS and DNS go through it, with no proxy settings and
no DNS settings anywhere.

Everything below the interception layer — DNS-over-HTTPS, the decision
ladder, TLS record fragmentation, learning, verification — is the same
code on every platform; only how traffic reaches the daemon differs
(see [Windows](#windows) and [macOS](#macos) for their interception).

## What it does

```
application
  │  DNS query (UDP/TCP 53, to any resolver — router, ISP, public)
  ├─────────────► nftables REDIRECT ─► 127.0.0.1:1053  DNS forwarder
  │                                       └─► DNS-over-HTTPS (Cloudflare,
  │                                           Google) — real answers,
  │                                           never a block page
  │  TCP connect to <real address>:443
  ├─────────────► nftables REDIRECT ─► 127.0.0.1:1091  transparent proxy
  │                                       ├─ original destination
  │                                       │  (SO_ORIGINAL_DST)
  │                                       ├─ hostname from the TLS
  │                                       │  ClientHello (SNI)
  │                                       └─► connects out itself,
  │                                           ClientHello possibly
  │                                           re-framed (see below)
  │  UDP 443 (QUIC) to a known-blocked address
  └─────────────► rejected ─► the application falls back to TCP
```

- **No TLS termination.** The client's own ClientHello is forwarded
  (at most re-framed into two TLS records); the application verifies
  the real server certificate itself. Nothing is decrypted.
- **Loop prevention.** Every socket the daemon opens carries
  `SO_MARK 0x2a4c`; the nftables rules skip *any* marked socket (ours,
  a VPN's, another proxy's), loopback, and private/link-local
  destinations (except DNS, below).
- **Fail-open.** The redirect rules only match while the daemon keeps
  refreshing a 30-second heartbeat element in nftables. If it stops,
  crashes, or hangs, interception ends on its own; a clean stop and
  systemd's `ExecStopPost` both delete the table immediately.

## DNS

Every outgoing DNS query — including one to the router, which is
typically the resolver that returns block-page addresses — is
redirected to a local forwarder and answered over DNS-over-HTTPS
(RFC 8484, HTTP/1.1, certificate verified). The DoH ClientHello is
itself sent TLS-record-fragmented. Only if every DoH server fails is
plain DNS (1.1.1.1, 8.8.8.8, 9.9.9.9 …) used. Loopback is not
intercepted, so the application → local stub resolver
(systemd-resolved) hop is unchanged; the stub's upstream queries are
what get redirected, and its cache keeps working.

`DPI_PROXY_TP_DNS=off` in the unit file leaves DNS alone.

## Choosing how to connect

For each connection the daemon decides, in this order:

1. a manual rule in `/etc/dpi-proxy/strategy.conf` (`pass`, `tlsrec`,
   `tlsrec-split`);
2. a cached decision for this host on this network;
3. the automatic ladder:
   - **known-blocked hosts** (Discord and a few others, built in):
     TLS record fragmentation straight away, the variant that last
     worked on this network first — no plain attempt that would only
     time out against the DPI;
   - **any other host:** a plain connection first; only if that gets
     no TLS answer, TLS record fragmentation (`tlsrec`, then
     `tlsrec-split`), and — if the trusted resolver disagrees with the
     address the application used — the trusted address.

A bypass that worked is cached per host and per network only after an
independent `openssl s_client` handshake over the same path verified
the server certificate for that hostname.

### Techniques

- `tlsrec` — the ClientHello is re-framed as two TLS records, split in
  the middle of the server name. Valid TLS (servers reassemble
  handshake messages across records); a DPI box that only parses the
  first record never sees the whole hostname.
- `tlsrec-split` — the same, plus the first few bytes go out in their
  own TCP segment.

Which one a network needs is found automatically. Neither changes
anything the server or the application can tell apart from a normal
connection.

## Operation

```sh
dpi-proxy-ctl status          # engine, DNS, counters, conflicts
dpi-proxy-ctl logs 50
dpi-proxy-ctl strategy discord.com
sudo dpi-proxy-ctl restart
sudo dpi-proxy-ctl stop       # internet keeps working, unbypassed
```

On Linux, logs go to the journal (`journalctl -u dpi-proxy-transparent`);
`DPI_PROXY_LOG_LEVEL=debug` logs every connection attempt. Learned
decisions live in `/var/lib/dpi-proxy/tp-decisions.conf`.

## Windows

The daemon is the same; interception uses the WinDivert driver
(third-party, signed, LGPLv3/GPLv2, shipped unmodified next to
`dpi-proxy.exe`) and the "reflection" technique from WinDivert's own
samples:

```
application  A:p  -> D:443        (outbound, captured)
rewritten    D:p  -> A:1091       (re-injected as inbound: the service's
                                   listener accepts it; the peer address
                                   (D, p) is the original destination)
service      A:1091 -> D:p        (captured)
rewritten    D:443 -> A:p         (re-injected inbound: the application
                                   sees its server answering)
```

DNS (UDP and TCP port 53) is reflected the same way to the forwarder on
port 1053.

- **Only flows it saw start** are reflected (TCP: the SYN), so
  connections that existed before the service started are untouched.
  The listeners (bound to all addresses, since reflected packets are
  addressed to the machine's own address) refuse any connection or
  query that is not in that flow table — they can't be used from the
  network.
- **Loop prevention:** the service's own sockets bind to local ports
  45000–45999, which the capture filter excludes (the equivalent of
  Linux's `SO_MARK`).
- **Fail-open:** diversion belongs to the service's WinDivert handle;
  when the process stops or dies, Windows stops diverting at once.
  The service is restarted automatically after a crash.
- **QUIC:** only QUIC long-header (handshake) packets are captured at
  all; those to known-blocked addresses are dropped.
- A Windows Firewall rule (`dpi-proxy`, inbound, this program only) lets
  the reflected connections reach the service.
- Logs: `%ProgramData%\dpi-proxy\dpi-proxy.log` (rotated at 4 MB);
  `dpi-proxy-ctl logs`.

## macOS

The daemon is the same; interception uses PF, the packet filter built
into macOS. PF's `rdr` only rewrites packets *arriving* on an
interface, which a Mac's own outgoing connections never do, so (as
sshuttle and mitmproxy do) the rules first route them to the loopback
interface, where they arrive:

```
application  A:p -> D:443   leaves by en0 (or any interface but lo0)
  pass out route-to (lo0 127.0.0.1)     -> the packet is sent to lo0
  rdr on lo0 ... -> 127.0.0.1:1091      -> it arrives at our listener
service      accept(): peer A:p; DIOCNATLOOK on /dev/pf asks PF's
             state table where A:p was going -> D:443
             connects out itself from a local port in 40000-48999
             (never intercepted), ClientHello possibly re-framed
reply        127.0.0.1:1091 -> A:p is translated back by the rdr
             state into D:443 -> A:p: the application sees its server
```

DNS (UDP and TCP port 53, to any server but loopback and IPv6
link-local) takes the same path to the forwarder on port 1053.

- **Only our own anchor.** All rules live in the PF anchor
  `com.apple/dpi-proxy`. macOS's own `/etc/pf.conf` evaluates every
  anchor under `com.apple/`, so neither `/etc/pf.conf` nor the loaded
  main ruleset is modified (if a custom main ruleset lacks the
  `rdr-anchor "com.apple/*"` / `anchor "com.apple/*"` lines, the daemon
  refuses to start and says so; only a completely empty main ruleset is
  reloaded from the system's unchanged `/etc/pf.conf`). Removing our
  rules flushes that anchor's rules and tables only — never other
  anchors, the main ruleset or PF's state table. (Once created, macOS
  keeps an anchor's *name* registered until reboot even when it is
  empty — no `pfctl` operation removes it, not even `-F all` — so
  after a stop or uninstall `pfctl -a com.apple -s Anchors` still
  lists an empty `com.apple/dpi-proxy`, like Apple's own empty
  anchors next to it. It holds no rules or tables and does nothing.)
- **PF on/off is reference-counted.** The daemon enables PF with
  `pfctl -E` and releases exactly that reference (`pfctl -X`) when it
  stops; PF is disabled again only if no other program holds a
  reference, i.e. it ends up as it was before.
- **Loop prevention:** every socket the daemon opens (upstream TCP,
  DoH, plain DNS, the certificate verifier) binds a local port in
  40000–48999 (below macOS's ephemeral range), and every rule skips
  those source ports — the equivalent of Linux's `SO_MARK`.
- **Private, loopback, link-local and multicast** destinations are not
  redirected for HTTPS; for DNS only loopback and IPv6 link-local /
  multicast servers are left alone (the router's resolver is the one
  that returns block pages). mDNS/Bonjour (`.local`, UDP 5353) is
  never touched.
- **DNS the trusted resolvers can't answer.** On macOS the forwarder
  also learns (from PF's state) which server a query was really sent
  to — normally the router — and uses it, never for a known-blocked
  name, for: local names (single-label names, `.local`, `.lan`,
  `.home`, `.home.arpa`, `.internal`, `.corp`, private reverse
  lookups), which are never sent to a public resolver; names the
  trusted resolvers call nonexistent (LAN hosts, a VPN's internal
  zones); and all names while every trusted resolver is failing, e.g.
  behind a captive portal before login, so the network stays usable.
- **Fail-open.** PF rules outlive the process that loaded them, so the
  daemon spawns a small watchdog process (the same binary,
  `--pf-watchdog`, in its own session) connected to it by a pipe.
  Daemon stops or crashes → the pipe closes → the watchdog removes the
  anchor's rules and releases the PF reference immediately. Daemon
  hangs → no heartbeat for 30 s → the watchdog removes the rules (the
  daemon reinstalls them if it recovers). A clean stop removes them
  itself. Only if the daemon and the watchdog are killed at the same
  instant do the rules stay until launchd restarts the daemon
  (`KeepAlive`, within about 10 s), which removes stale rules and
  references first. Nothing is written to disk that survives a reboot
  except the launchd job itself.
- **QUIC:** UDP/443 to addresses in the anchor's `dpi_quic4` /
  `dpi_quic6` tables is refused (`block return`), so browsers fall back
  to TCP for exactly those destinations.
- **Network changes** (Wi-Fi change, reconnect, sleep/wake) arrive on a
  routing socket; the rules are interface-independent, so they keep
  working on any new interface. The network profile is the default
  route's interface, gateway and gateway MAC address.
- Files: `/usr/local/bin/dpi-proxy`, `/usr/local/bin/dpi-proxy-ctl`,
  `/Library/LaunchDaemons/io.github.kadireren7.dpi-proxy.plist`,
  `/usr/local/etc/dpi-proxy/strategy.conf`,
  `/usr/local/var/dpi-proxy/tp-decisions.conf`, the status file and PF
  reference token in `/var/run/dpi-proxy/`, log
  `/var/log/dpi-proxy.log` (rotated at 4 MB; `dpi-proxy-ctl logs`).
  `sudo ./uninstall.sh` removes all of them.

## Limitations

- TCP/443 (HTTPS) and DNS only. Other UDP — voice/video calls, games —
  is not touched; if a network blocks those at the UDP level this tool
  does not help.
- Only one transparent interceptor can run at a time. If another DPI
  tool with its own nftables redirects (for example the `dpi-bypass`
  service) is active, the daemon logs a `[conflict]` warning and
  `dpi-proxy-ctl status` shows it; stop one of them.
- Blocking by IP address, or DPI that reassembles TLS records, cannot
  be bypassed this way.
