# Linux

Linux transparent mode is the original, most mature platform here:
nftables redirects outgoing HTTPS and DNS to the local `dpi-proxy`
service, which applies DNS-over-HTTPS, TLS record fragmentation and
per-network learning. Real ISP/DPI field-tested.

## Install

```sh
git clone https://github.com/kadireren7/dpi-for-everyone.git
cd dpi-for-everyone
sudo ./scripts/install.sh
```

The installer builds from source (installs `libssl-dev` with
`apt-get` if missing; also needs `build-essential`, `nftables` and
`openssl`), installs the `dpi-proxy-transparent` systemd service,
starts it, checks DNS and HTTPS through it, and enables it at boot.
That's all — nothing to configure afterwards. If another transparent
DPI tool (e.g. `dpi-bypass`) is active, the installer warns but still
installs; stop one of them, running two at once breaks both.

## Commands

```sh
dpictl status                # short summary
dpictl status --verbose      # full detail (nft counters as root)
dpictl doctor                # health checks, PASS/WARN/FAIL
dpictl diagnose discord.com  # DNS + HTTPS check for one site
dpictl logs 50
dpictl support-bundle        # local diagnostics archive, redacted, no telemetry
dpictl strategy discord.com  # what applies to a site right now
sudo dpictl restart
sudo dpictl stop              # until next start/boot
```

`dpi-proxy-ctl` still works with the same commands — a compatibility
alias for `dpictl`. See [cli.md](cli.md) for the full command
reference (shared across platforms).

Optional manual rules go in `/etc/dpi-proxy/strategy.conf` (e.g.
`example.com = tlsrec`); none are needed.

Files: `/usr/local/bin/dpi-proxy`, `/usr/local/bin/dpictl`,
`/etc/dpi-proxy/strategy.conf`, `/var/lib/dpi-proxy/tp-decisions.conf`
(learned decisions), status file and nftables table `inet
dpi_proxy_tp`, systemd unit `dpi-proxy-transparent.service`. Logs go
to the journal: `journalctl -u dpi-proxy-transparent`
(`DPI_PROXY_LOG_LEVEL=debug` in the unit for a line per connection).

## Update / uninstall

```sh
git pull && sudo ./scripts/install.sh   # rebuilds and restarts; config kept
sudo ./scripts/uninstall.sh             # removes service, binaries, nftables table
sudo ./scripts/uninstall.sh --purge     # ...and /etc/dpi-proxy
```

## Troubleshooting

```sh
dpictl doctor                    # service/interception/DNS/reachability/conflicts
dpictl diagnose discord.com      # DNS + HTTPS for one site
dpictl logs 100
dpictl support-bundle            # redacted archive to attach to a bug report
```

`doctor` also flags other known DPI tools (`dpi-bypass`, zapret's
`nfqws`, GoodbyeDPI) and VPN/tunnel interfaces that might interfere,
without disabling anything it finds — stop the other one yourself.

## Packet mode (optional, advanced)

An older NFQUEUE-based engine (`dpi-proxy-packet`, strategies
`split`/`disorder`/`fake`/`fragment`) is still included for
experimentation: `sudo ./scripts/install.sh --packet` builds it
(needs `libnetfilter-queue-dev`) but does not start it. Transparent
mode replaces it as the automatic engine. See
[packet-mode.md](packet-mode.md).

## SOCKS5 mode

`dpi-proxy` run without arguments is a plain local SOCKS5 proxy on
`127.0.0.1:1080` (`DPI_PROXY_SPLIT_TLS=record ./dpi-proxy` for the
bypass) — on every platform, not just Linux.

See also: [../README.md](../README.md) for the platform-independent
limitations, and [transparent-mode.md](transparent-mode.md) for how
the engine itself works.
