# dpi-for-everyone

`dpi-proxy` gets HTTPS traffic past SNI-based DPI (deep packet
inspection) filtering. On Linux (and, in beta, on Windows and macOS) it
runs as a system service: after one install command, blocked sites and
apps work in every browser and application, with **no proxy settings
and no DNS changes**.

It runs entirely on your own machine. It is not a VPN, it does not
tunnel through a remote server, and it never decrypts or
man-in-the-middles TLS.

## Platforms

| Platform | What you get | Validation |
|---|---|---|
| Linux | **Transparent automatic mode** | Real ISP/DPI field-tested |
| Windows 10/11 (x64) | **Transparent automatic mode (Beta)** | Fully end-to-end tested on real Windows GitHub runners with the real WinDivert driver; **real ISP/DPI field validation still pending** |
| macOS (Apple silicon, Intel) | **Transparent automatic mode (Beta)** | Fully end-to-end tested on real macOS GitHub runners (macOS 14, 15 and 26 on Apple silicon, macOS 15 on Intel) with real PF and launchd; **not yet tested on a physical Mac or against real ISP DPI** |

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

## Windows (Beta)

Windows transparent mode works the same way as on Linux and passes the
full automated end-to-end test on real Windows machines, but it has
**not yet been validated against real ISP DPI**. Field reports are
welcome.

### Quick start

1. Download **`dpi-proxy-windows-x86_64.zip`** from
   [Releases](https://github.com/kadireren7/dpi-for-everyone/releases)
   (v1.1.0-rc1 or newer) and extract it.
2. Open **PowerShell as Administrator** in the extracted folder and run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1
   ```

3. Check it:

   ```powershell
   .\dpi-proxy-ctl status        # in a new PowerShell window: dpi-proxy-ctl status
   ```

   You should see `engine: running`.
4. Use Firefox, Chrome, Discord, … normally. No proxy arguments, no
   manual DNS changes, no per-app configuration.

Everything needed is in the ZIP (`dpi-proxy.exe`, `dpi-proxy-ctl`,
`install.ps1`, `uninstall.ps1`, the WinDivert driver files and license,
`WINDOWS-QUICKSTART.txt`). No Visual Studio, MinGW, Git or Python; the
installer puts `dpi-proxy-ctl` on the PATH itself.

Before testing, stop GoodbyeDPI, zapret, other DPI tools and VPN packet
filters.

### Commands

```powershell
dpi-proxy-ctl status
dpi-proxy-ctl diagnose discord.com   # DNS + HTTPS check for one site
dpi-proxy-ctl logs 50
dpi-proxy-ctl stop                   # (Administrator) normal internet, no bypass
dpi-proxy-ctl start                  # (Administrator)
dpi-proxy-ctl restart                # (Administrator)
```

Files: `%ProgramFiles%\dpi-proxy` (program), `%ProgramData%\dpi-proxy`
(`strategy.conf`, learned decisions, `dpi-proxy.log`).

### Uninstall

PowerShell as Administrator, in the extracted folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1          # keeps settings/logs
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Purge   # removes them too
```

Removes the service, program folder, firewall rule and PATH entry, and
unloads the WinDivert driver unless another program is using it.

### WinDivert

Windows interception uses [WinDivert](https://reqrypt.org/windivert.html),
a **third-party, signed** packet interception driver (LGPLv3/GPLv2) —
not our code — shipped unmodified in the ZIP with its license. It
redirects this computer's own outgoing HTTPS and DNS to the local
service, and stops the moment the service stops or crashes (fail-open).
Windows Defender or other antivirus software may warn about it because
DPI tools use it.

## macOS (Beta)

macOS transparent mode works the same way as on Linux: the built-in
macOS packet filter (PF) sends this Mac's HTTPS and DNS to the local
`dpi-proxy` service. It passes the full automated end-to-end test on
real macOS machines, but it has **not yet been tested on a physical Mac
or against real ISP DPI**. Field reports are welcome.

### Quick start

1. Download **`dpi-proxy-macos-arm64.zip`** (Apple silicon: M1/M2/M3/…)
   or **`dpi-proxy-macos-x86_64.zip`** (Intel Macs) from
   [Releases](https://github.com/kadireren7/dpi-for-everyone/releases)
   (v1.2.0-rc1 or newer) and double-click it to extract it.
2. Open **Terminal** in the extracted folder and install:

   ```sh
   cd ~/Downloads/dpi-proxy-macos-arm64
   sudo ./install.sh
   ```

3. Check it: `dpi-proxy-ctl status` — you should see `engine: running`.
4. Use Safari, Chrome, Firefox, Discord, … normally. No proxy settings,
   no manual DNS changes, no per-app configuration.

The ZIP contains everything (`dpi-proxy`, `dpi-proxy-ctl`,
`install.sh`, `uninstall.sh`, the launchd job, LICENSE,
`MACOS-QUICKSTART.txt`); no Xcode, Homebrew, Git or Python is needed.
Before testing, quit SpoofDPI, ByeDPI, zapret and VPN apps that filter
traffic.

### Commands

```sh
dpi-proxy-ctl status
dpi-proxy-ctl diagnose discord.com   # DNS + HTTPS check for one site
dpi-proxy-ctl logs 50
sudo dpi-proxy-ctl stop              # normal internet, no bypass (until start/reboot)
sudo dpi-proxy-ctl start
sudo dpi-proxy-ctl restart
```

Files: `/usr/local/bin/dpi-proxy`, `/usr/local/bin/dpi-proxy-ctl`,
`/Library/LaunchDaemons/io.github.kadireren7.dpi-proxy.plist`,
`/usr/local/etc/dpi-proxy/strategy.conf`, log `/var/log/dpi-proxy.log`.

### Uninstall

In the extracted folder: `sudo ./uninstall.sh`. It removes the service,
the programs, settings, learned decisions, logs and dpi-proxy's PF
rules, and releases its PF reference; PF, `/etc/pf.conf` and every
other rule are left exactly as they were.

### How it touches the system

All rules live in dpi-proxy's own PF anchor (`com.apple/dpi-proxy`);
`/etc/pf.conf` is never edited and other PF rules are never touched.
If the service stops, crashes or hangs, a watchdog process removes the
rules (immediately, or within 30 seconds for a hang), so the internet
keeps working, just unbypassed. Details:
[docs/transparent-mode.md](docs/transparent-mode.md#macos).

### SOCKS5 mode

`dpi-proxy` run without arguments is still a plain local SOCKS5 proxy on
`127.0.0.1:1080` (`DPI_PROXY_SPLIT_TLS=record ./dpi-proxy` for the
bypass), on every platform.

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
  (dpi-bypass, GoodbyeDPI, zapret, …) alongside it; the service warns if
  it detects one.
- **Windows (Beta):** not yet validated against real ISP DPI. IPv6
  interception and the QUIC fallback are implemented but not yet
  exercised by the automated test (the test machines have no IPv6).
  All traffic to port 443 passes through the service in user space,
  which costs some throughput compared to Linux; performance on
  consumer machines is still to be measured.
- **macOS (Beta):** not yet tested on a physical Mac or against real
  ISP DPI (CI machines are virtual machines on Apple hardware). DNS
  servers with IPv6 link-local addresses (`fe80::…`) are not
  intercepted; if a network hands out only such a resolver, names are
  resolved by it unprotected. A custom `/etc/pf.conf` without Apple's
  `com.apple/*` anchor hooks is not supported (the service says so and
  does not start).

## Documentation

- [docs/transparent-mode.md](docs/transparent-mode.md) — how the
  engine works (Linux, Windows, macOS): DNS, the decision ladder,
  fail-open, operation.
- [docs/development.md](docs/development.md) — building, tests,
  sanitizers, CI.
- [docs/packet-mode.md](docs/packet-mode.md),
  [docs/architecture.md](docs/architecture.md),
  [docs/discovery.md](docs/discovery.md),
  [docs/network-profiles.md](docs/network-profiles.md) — the optional
  packet-mode engine.

## License

MIT — see [LICENSE](LICENSE).
