# Development

Building, testing, and CI for dpi-proxy. For how the engine works
internally, see [docs/architecture.md](architecture.md) and
[docs/transparent-mode.md](transparent-mode.md).

## SOCKS5 proxy details

- Listens on `127.0.0.1:1080` by default.
- SOCKS5 address types supported: `0x01` (IPv4), `0x03` (DOMAIN),
  `0x04` (IPv6).
- Only TCP `CONNECT` is supported (no UDP).
- TLS is not intercepted or decrypted (no MITM) — same property as
  packet mode, see [docs/architecture.md](architecture.md).

## CLI reference

`dpi-proxy` (SOCKS5 proxy, all platforms):

```
dpi-proxy [--listen HOST:PORT] [--log-level error|info]
          [--capabilities] [--version] [--help]
```

`dpi-proxy-packet` (Linux packet mode) has its own reference in
[docs/packet-mode.md](packet-mode.md#cli-reference).

Both binaries print an actionable message (not a bare error code) on
common startup failures: an address already in use, a malformed
strategy config (with the offending line number), missing
`libnetfilter-queue-dev`, or missing `nft`/capabilities.

## Building from source

```sh
# Linux — SOCKS5 proxy + transparent mode (needs libssl-dev)
# macOS — the same, if OpenSSL is found (Homebrew's openssl@3 by
#         default, or OPENSSL_PREFIX=...); otherwise SOCKS5 only
make fclean && make
./dpi-proxy
```

```sh
# macOS release build: static OpenSSL 3.5 LTS (SHA-256-pinned source),
# binary depends on macOS system libraries only, runs on macOS >= 11
export MACOSX_DEPLOYMENT_TARGET=11.0
./scripts/macos/build-openssl.sh "$PWD/../openssl-$(uname -m)"
make fclean && make OPENSSL_PREFIX="$PWD/../openssl-$(uname -m)" OPENSSL_STATIC=1
./scripts/macos/package.sh dpi-proxy-macos-$(uname -m)   # the test package folder
```

```sh
# Linux — packet mode (see docs/packet-mode.md)
make packet-mode
```

```sh
# Windows, cross-compiled from Linux/macOS with mingw-w64
# requires the toolchain, e.g. `apt install mingw-w64`
make windows
```

`make windows` produces a statically linked `dpi-proxy.exe` that runs
on a plain Windows machine without extra runtime DLLs.

## Tests

```sh
make test        # unit tests, plain build
make sanitize     # same unit tests, forced clean rebuild under ASan+UBSan
```

`make sanitize` always runs `make clean` first — if it didn't, stale
plain `.o` files from a prior `make test` could slip through
uninstrumented. `make packet-mode` does the same for the reverse
direction (a prior `make sanitize` leaving instrumented `.o` files that
would otherwise get linked into `dpi-proxy-packet` unsanitized) — see
the comment above the `packet-mode` target in the `Makefile` if you're
touching either.

`test_nft_rules` only exercises its unprivileged-failure path when run
as a normal user; running `make test` as root additionally exercises
the real `nft` success path.

## CI

`.github/workflows/build.yml` runs on every push/PR:

- `linux`, `windows`: `make re` (or `make windows`) + a smoke
  test (SOCKS5 proxy against a real `curl` request) + `--version`/
  `--capabilities`/`--help` CLI checks.
- `macos` (arm64 on macos-15, x86_64 on macos-15-intel): the release
  build (static OpenSSL), `make test`, `make sanitize`, binary checks
  (architecture, minimum macOS version, system-only libraries), SOCKS5
  smoke test, and the zipped test package as an artifact.
- `macos-e2e` (macOS 14, 15, 26 on Apple silicon; 15 on Intel): the
  zipped package extracted and installed as a tester would, then
  `scripts/macos/e2e-test.sh`: real PF interception, original
  destination recovery, DoH, QUIC reject table, IPv6 (where the
  runner has it), no loop, forced bypass, ctl, restart, stop, SIGKILL
  and SIGSTOP fail-open, launchd restart, uninstall leaving nothing
  behind, clean reinstall.
- `linux-e2e`, and the Windows job's end-to-end step: the same
  lifecycle for Linux and Windows.
- `sanitize`: `make sanitize`.
- `packet-mode-compile`: installs real `libnetfilter-queue-dev` +
  `nftables` via `sudo apt-get`, runs `make packet-mode`, and runs
  `./dpi-proxy-packet --capabilities` (read-only — does not apply
  nftables rules or bind a live NFQUEUE; GitHub-hosted runners aren't a
  confirmed-reliable place to do that; live verification is done on
  real machines with `scripts/field-test-linux.sh`).
- `sanitize-then-packet-mode`: runs `make sanitize` immediately
  followed by `make packet-mode` in one workspace — regression
  coverage for the stale-object-file class of bug described above.

## Release builds

Prebuilt releases (packet mode is Linux-only and needs
root/capabilities, so it's a build-from-source thing, not a release
artifact) are published on the
[releases page](https://github.com/kadireren7/dpi-for-everyone/releases)
for each tag: `dpi-proxy-linux-x86_64`, `dpi-proxy-windows-x86_64.zip`,
and (from v1.2.0-rc1) `dpi-proxy-macos-arm64.zip` /
`dpi-proxy-macos-x86_64.zip`, alongside a `SHA256SUMS` file. Every
package is built only after it passed its platform's end-to-end test:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

`dpi-proxy --version` reports the version baked in at build time (from
the repo's `VERSION` file) — it will match the release tag for any
official build.

## Optional: TLS ClientHello splitting in the SOCKS5 proxy

Separate from packet mode's `SPLIT` strategy. Set
`DPI_PROXY_SPLIT_TLS=1` before starting the SOCKS5 proxy to make it
split the first TLS ClientHello across two TCP segments, mid-hostname:

```sh
DPI_PROXY_SPLIT_TLS=1 ./dpi-proxy
```

**It's off by default because testing showed it reliably breaks the
handshake against at least Cloudflare-fronted hosts** (the upstream
server closes the connection right after the split write), while
leaving other hosts unaffected. Enable it only if you've verified it
actually helps for the sites you care about, on your own network —
otherwise it will make things worse, not better.
