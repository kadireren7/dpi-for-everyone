#!/usr/bin/env bash
# Assembles the Windows release folder: dpi-proxy.exe, the unmodified
# official WinDivert runtime files and license, and the install /
# uninstall / control scripts. Usage: package.sh <out-dir>
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
OUT="${1:?usage: package.sh <out-dir>}"
WD="$ROOT/third_party/WinDivert-2.2.2-A"
mkdir -p "$OUT"
cp "$ROOT/dpi-proxy.exe" "$OUT/"
cp "$WD/x64/WinDivert.dll" "$WD/x64/WinDivert64.sys" "$OUT/"
cp "$WD/LICENSE" "$OUT/WinDivert-LICENSE.txt"
cp "$ROOT/LICENSE" "$OUT/LICENSE.txt"
cp "$ROOT"/scripts/windows/{install.ps1,uninstall.ps1,Install.cmd,Uninstall.cmd,dpictl-impl.ps1,dpictl.cmd,dpi-proxy-ctl.cmd,WINDOWS-QUICKSTART.txt} "$OUT/"
ls -l "$OUT"
