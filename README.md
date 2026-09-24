# dpi-for-everyone

`dpi-proxy` gets HTTPS traffic past SNI-based DPI (deep packet
inspection) filtering. On Linux it runs as a system service: after one
install command, blocked sites and apps work in every browser and
application, with **no proxy settings and no DNS changes**. On Windows
and macOS it is a local SOCKS5 proxy.

It runs entirely on your own machine. It is not a VPN, it does not
tunnel through a remote server, and it never decrypts or
man-in-the-middles TLS.

## Platforms

| Platform | What you get |
|---|---|
| Linux | **Transparent mode** — automatic, system-wide (recommended) |
| Windows | SOCKS5 proxy only |
| macOS | SOCKS5 proxy only |

`dpi-proxy --capabilities` prints what the binary you have supports.

## Linux

### Install

```sh
git clone https://github.com/kadireren7/dpi-for-everyone.git
cd dpi-for-everyone
sudo ./scripts/install.sh
```

The installer builds from source (it installs `libssl-dev` with
`apt-get` if missing; it also needs `build-essential`, `nftables` and
`openssl`), installs the `dpi-proxy-transparent` systemd service,
starts it, checks DNS and HTTPS through it, and enables it at boot.
That's all — nothing to configure afterwards.

### What it does

- **System-wide HTTPS interception.** nftables redirects outgoing
  TCP/443 to a local transparent proxy. Every application is covered;
  none needs a proxy setting.
- **Protection from poisoned DNS.** Every outgoing DNS query, including
  queries to your router, is answered by an internal
  DNS-over-HTTPS forwarder (Cloudflare, Google), so blocked names
  resolve to their real addresses instead of block pages.
- **Automatic DPI bypass.** Known-blocked services (Discord and a few
  others) get the bypass on the first connection; any other site is
  tried normally first, and a bypass is learned — per site and per
  network — only if it's needed.
- **TLS record fragmentation.** The bypass re-frames the TLS
  ClientHello into two records split inside the server name (plus an
  optional TCP split), which is valid TLS but hides the name from a DPI
  that parses one record.
- **QUIC fallback.** QUIC (UDP/443) to bypassed destinations is
  rejected, so browsers and apps fall back to TCP, where the bypass
  works.
- **Fail-open.** If the service stops, crashes or hangs, interception
  ends on its own within 30 seconds (immediately on a normal stop); your
  connection keeps working, just unbypassed.

Details: [docs/transparent-mode.md](docs/transparent-mode.md).

### Everyday use

```sh
dpi-proxy-ctl status                # engine, DNS, counters
dpi-proxy-ctl logs 50               # recent log lines
dpi-proxy-ctl strategy discord.com  # what applies to a site right now
sudo dpi-proxy-ctl restart
sudo dpi-proxy-ctl stop             # until next start/boot
```

Optional manual rules go in `/etc/dpi-proxy/strategy.conf` (e.g.
`example.com = tlsrec`); none are needed.

### Update / uninstall

```sh
git pull && sudo ./scripts/install.sh   # rebuilds and restarts; config kept
sudo ./scripts/uninstall.sh             # removes service, binaries, nftables table
sudo ./scripts/uninstall.sh --purge     # ...and /etc/dpi-proxy
```

### Packet mode (optional, advanced)

An older NFQUEUE-based engine (`dpi-proxy-packet`, strategies
`split`/`disorder`/`fake`/`fragment`) is still included for
experimentation: `sudo ./scripts/install.sh --packet` builds it
(needs `libnetfilter-queue-dev`) but does not start it. Transparent
mode replaces it as the automatic engine. See
[docs/packet-mode.md](docs/packet-mode.md).

## Windows and macOS

SOCKS5 proxy only — no system-wide interception, no DNS protection.
Download the binary from the
[latest release](https://github.com/kadireren7/dpi-for-everyone/releases/latest):

```powershell
# Windows
iwr "https://github.com/kadireren7/dpi-for-everyone/releases/latest/download/dpi-proxy-windows-x86_64.exe" -OutFile dpi-proxy.exe
$env:DPI_PROXY_SPLIT_TLS = "record"
.\dpi-proxy.exe
```

```sh
# macOS (Apple silicon)
curl -fsSL "https://github.com/kadireren7/dpi-for-everyone/releases/latest/download/dpi-proxy-macos-arm64" -o dpi-proxy && chmod +x dpi-proxy
DPI_PROXY_SPLIT_TLS=record ./dpi-proxy
```

It listens on `127.0.0.1:1080`; point an application's SOCKS5 setting
there. Without `DPI_PROXY_SPLIT_TLS=record` it relays traffic
unmodified. Names are resolved with the system resolver, so if your
network poisons DNS you also need to set a trustworthy DNS server
yourself. Stop it with `Ctrl+C`; remove it by deleting the file.

## Limitations

- **Not a VPN.** Traffic leaves from your own connection with your own
  IP address. Sites blocked by IP address, or services that block your
  region, are not reachable this way.
- **HTTPS and DNS only.** Other UDP traffic — voice and video calls,
  game traffic — is not touched. If a network blocks those at the UDP
  level, this tool does not help (e.g. Discord text and media work,
  voice may not).
- **Network-dependent.** DPI systems differ between ISPs and change
  over time. The techniques used here work against DPI that inspects
  the TLS server name without reassembling TLS records; they are not
  guaranteed to bypass every censorship system.
- **One interceptor at a time.** Don't run another transparent DPI tool
  alongside it; the service warns if it detects one.
- **No decryption, ever.** Only cleartext handshake bytes are read or
  re-framed; certificates are verified by your applications as usual.

## Documentation

- [docs/transparent-mode.md](docs/transparent-mode.md) — how the Linux
  engine works: DNS, the decision ladder, fail-open, operation.
- [docs/development.md](docs/development.md) — building, tests,
  sanitizers, CI.
- [docs/packet-mode.md](docs/packet-mode.md),
  [docs/architecture.md](docs/architecture.md),
  [docs/discovery.md](docs/discovery.md),
  [docs/network-profiles.md](docs/network-profiles.md) — the optional
  packet-mode engine.

## License

MIT — see [LICENSE](LICENSE).
