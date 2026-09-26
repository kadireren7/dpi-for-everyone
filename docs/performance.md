# Performance and package size

Measured on real CI runners (GitHub Actions: `ubuntu-latest`,
`windows-latest`, `macos-15`/`macos-15-intel`), not estimated. "Before"
is the v1.4 checkpoint commit (before any size/performance work in
v1.6); "after" is with the changes below applied.

## What changed

- **Strip debug/symbol info from every packaged binary.** The source
  tree's own build (`make all`/`make re`) is left unstripped for local
  debugging; only the copy that gets installed or zipped is stripped
  (`scripts/install.sh`, `scripts/macos/package.sh`,
  `scripts/windows/package.sh`, and the Linux release job). WinDivert's
  driver files are never touched — shipped unmodified, as documented.
  Pure metadata removal: no behavior change.
- **Link-time dead-code elimination**: `-ffunction-sections
  -fdata-sections` at compile time, `--gc-sections` (Linux, and
  Windows via MinGW, always) or `-dead_strip` (macOS's Apple ld64,
  which doesn't understand `--gc-sections` at all) at link time. Lets
  the linker drop whole functions/data the binary never calls — most
  of the win here is against the statically-linked OpenSSL on Windows
  and macOS, where this binary only ever exercises a small slice of it
  (a TLS client and a DoH HTTPS client), not OpenSSL's full surface.

## Explicitly not done: dynamic OpenSSL

Windows and macOS statically link OpenSSL *by design*, so the shipped
binary depends on nothing but the OS (see `scripts/macos/build-openssl.sh`
and the Makefile's `OPENSSL_STATIC` notes) — Windows ships no OpenSSL
at all, and macOS removed public `libssl` headers/dylibs years ago.
Switching to dynamic linking would shrink the binary but reintroduce
exactly the runtime-dependency fragility (missing or mismatched system
OpenSSL) that static linking was chosen to avoid. That tradeoff was
considered and rejected, not overlooked — the milestone explicitly
forbids sacrificing reliability or rewriting the working TLS/DNS
implementation for package size.

## Binary size, before -> after

| Platform | Before | After | Change |
|---|---|---|---|
| Linux (`dpi-proxy`, dynamic OpenSSL) | 137,488 B | 113,312 B | -17.6% |
| Windows (`dpi-proxy.exe`, static OpenSSL) | 7,646,856 B | 6,018,560 B | -21.3% |
| macOS arm64 (`dpi-proxy`, static OpenSSL) | 5,477,032 B | 4,296,184 B | -21.6% |
| macOS x86_64 (`dpi-proxy`, static OpenSSL) | 5,976,976 B | 4,781,152 B | -20.0% |

The Windows/macOS "before" numbers are well above the ~2.7-3 MB and
~2-3 MB figures sometimes assumed for this project — the real,
measured pre-v1.6 numbers were 5.2-7.3 MB, almost entirely from static
OpenSSL. Even after this milestone's safe reductions, both remain
above the ~2-3 MB range; closing that further would mean giving up
static linking's reliability guarantee (see above) or a deeper,
higher-risk OpenSSL rebuild (minimal `./config` feature set) that
wasn't attempted this round — see "Not pursued this round" below.

## Package size breakdown

**Linux**: no separate package — `dpi-proxy` (113 KB stripped) is
installed directly by `scripts/install.sh`; `dpictl`/`dpi-proxy-ctl`
(shell scripts, a few KB each) and the systemd unit files are the only
other installed files.

**Windows ZIP** (`dpi-proxy-windows-x86_64.zip`):

| Component | Size |
|---|---|
| `dpi-proxy.exe` (our executable, stripped) | 6,018,560 B |
| `WinDivert.dll` + `WinDivert64.sys` (third-party driver, unmodified) | ~142 KB |
| Scripts (`install.ps1`, `uninstall.ps1`, `Install.cmd`, `Uninstall.cmd`, `dpictl.cmd`, `dpi-proxy-ctl.cmd`, `dpictl-impl.ps1`) | ~26 KB |
| `LICENSE.txt`, `WinDivert-LICENSE.txt`, `WINDOWS-QUICKSTART.txt` | ~3 KB |

Our own executable is over 97% of the package; WinDivert (required for
transparent mode, never removed) is a small fraction of it.

**macOS ZIP** (`dpi-proxy-macos-<arch>.zip`):

| Component | Size (arm64) |
|---|---|
| `dpi-proxy` (our executable, stripped, static OpenSSL) | 4,296,184 B |
| Scripts (`install.sh`, `uninstall.sh`, `Install.command`, `Uninstall.command`, `dpictl`, `dpi-proxy-ctl`) | ~29 KB |
| `io.github.kadireren7.dpi-proxy.plist`, `LICENSE`, `MACOS-QUICKSTART.txt` | ~5 KB |

No separate driver/runtime component on macOS (PF is built into the
OS); our own executable is essentially the whole package.

## Resource use (measured live in CI e2e, real installs)

| Platform | Startup (install/restart -> `engine: running`) | Idle RSS/working set | Under load | Threads | Throughput (50 MB download through the proxy) |
|---|---|---|---|---|---|
| Linux | 0.33 s | 8.7 MB | 10.2 MB, 14.5% CPU | 6 | 79.7 MB/s |
| Windows | 1.28 s | 19.0 MB | 20.5 MB | 17 | 45.2 MB/s |
| macOS (arm64) | (measured at install; not re-timed here) | 7.8 MB (+1.6 MB watchdog) | 0.5% CPU | - | 129.4 MB/s |

These are single-run CI numbers on shared runners (not dedicated
benchmark hardware), meant to establish an order of magnitude and to
be re-measured against, not as precise/reproducible-to-the-percent
benchmarks. Windows' larger footprint (thread count, working set, and
CPU) reflects doing packet interception in user space (WinDivert),
already documented as a known Windows-beta cost/limitation, unrelated
to this milestone's changes. RSS/CPU were not expected to move
materially from stripping/dead-code-elimination (those affect on-disk
size, not the memory footprint of code paths the process actually
executes) and weren't separately re-measured pre/post for that reason.

## Not pursued this round

- **A minimal OpenSSL build** (`./config no-legacy no-...`) for the
  static Windows/macOS builds would likely shrink the static libraries
  further before `--gc-sections`/`-dead_strip` even runs, but Windows
  gets its static OpenSSL from a prebuilt MSYS2 package (no control
  over its build flags at all), and reconfiguring macOS's from-source
  build (`scripts/macos/build-openssl.sh`) carries real risk of
  breaking something the current pinned build has already proven
  reliable, for a size payoff this round didn't have time to verify as
  safely as the changes actually made. Worth a future, dedicated pass
  with full CI verification, not squeezed into this one.
- Architecture-specific minimal packages, further archive-compression
  tuning: not attempted; current packages are already single-arch ZIPs
  with no dev-only files bundled.
