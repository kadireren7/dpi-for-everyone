#!/usr/bin/env bash
# Downloads the official WinDivert 2.2.2 release (signed driver, LGPLv3/
# GPLv2) into third_party/, for building and packaging the Windows
# binary. The archive's SHA-256 is pinned: a different file is refused.
set -euo pipefail
VERSION="2.2.2-A"
SHA256="63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15"
URL="https://reqrypt.org/download/WinDivert-$VERSION.zip"
DEST="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)/third_party"
mkdir -p "$DEST"
cd "$DEST"
if [ ! -d "WinDivert-$VERSION" ]; then
	curl -fsSL -o "WinDivert-$VERSION.zip" "$URL"
	echo "$SHA256  WinDivert-$VERSION.zip" | sha256sum -c -
	unzip -q "WinDivert-$VERSION.zip"
	rm -f "WinDivert-$VERSION.zip"
fi
echo "WinDivert SDK: $DEST/WinDivert-$VERSION"
