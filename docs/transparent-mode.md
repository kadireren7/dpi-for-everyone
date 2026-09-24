# Transparent mode (Linux)

`dpi-proxy --mode transparent`, run by the `dpi-proxy-transparent`
systemd service. It is the recommended way to use dpi-for-everyone on
Linux: after `sudo ./scripts/install.sh` every application's HTTPS and
DNS go through it, with no proxy settings and no DNS settings anywhere.

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

Logs go to the journal (`journalctl -u dpi-proxy-transparent`);
`DPI_PROXY_LOG_LEVEL=debug` logs every connection attempt. Learned
decisions live in `/var/lib/dpi-proxy/tp-decisions.conf`.

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
