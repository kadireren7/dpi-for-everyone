#!/bin/sh
# Assembles the macOS test package folder from a built dpi-proxy:
#   package.sh <out-dir>
# (the folder is then zipped with: ditto -c -k --keepParent <out-dir> <zip>)
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:?usage: package.sh <out-dir>}"
mkdir -p "$OUT"
install -m 755 "$ROOT/dpi-proxy" "$OUT/dpi-proxy"
# Strip the packaged copy only (debug symbols, not needed at
# runtime); the build tree's own dpi-proxy is untouched.
strip "$OUT/dpi-proxy"
for f in install.sh uninstall.sh Install.command Uninstall.command dpictl dpi-proxy-ctl; do
	install -m 755 "$ROOT/scripts/macos/$f" "$OUT/$f"
done
install -m 644 "$ROOT/scripts/macos/io.github.kadireren7.dpi-proxy.plist" "$OUT/"
install -m 644 "$ROOT/scripts/macos/MACOS-QUICKSTART.txt" "$OUT/"
install -m 644 "$ROOT/LICENSE" "$OUT/LICENSE"
# what the binary needs at run time: macOS system libraries only
if otool -L "$OUT/dpi-proxy" | tail -n +2 | grep -v -e '^[[:space:]]*/usr/lib/' -e '^[[:space:]]*/System/'; then
	echo "package.sh: dpi-proxy links a non-system library (see above)" >&2
	exit 1
fi
ls -l "$OUT"
