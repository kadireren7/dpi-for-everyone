#!/bin/sh
# Builds the static OpenSSL (3.5 LTS, SHA-256-pinned official release)
# that the macOS release binary links, so the binary needs nothing but
# macOS itself. Headers and libssl.a/libcrypto.a go to PREFIX; nothing
# is installed system-wide.
#
#   build-openssl.sh PREFIX [arm64|x86_64]
#   make OPENSSL_PREFIX=PREFIX OPENSSL_STATIC=1
#
# An existing PREFIX/lib/libssl.a is reused (CI caches PREFIX).
set -eu

VERSION=3.5.8
SHA256=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2
URL="https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"

PREFIX="${1:?usage: build-openssl.sh PREFIX [arm64|x86_64]}"
ARCH="${2:-$(uname -m)}"
: "${MACOSX_DEPLOYMENT_TARGET:=11.0}"
export MACOSX_DEPLOYMENT_TARGET

case "$ARCH" in
arm64) TARGET=darwin64-arm64-cc ;;
x86_64) TARGET=darwin64-x86_64-cc ;;
*) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

if [ -f "$PREFIX/lib/libssl.a" ] && [ -f "$PREFIX/lib/libcrypto.a" ]; then
	echo "OpenSSL already built in $PREFIX"
	exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -fsSL -o "$WORK/openssl.tar.gz" "$URL"
echo "$SHA256  $WORK/openssl.tar.gz" | shasum -a 256 -c -
tar -xzf "$WORK/openssl.tar.gz" -C "$WORK"
cd "$WORK/openssl-$VERSION"
# --openssldir: OpenSSL's default CA bundle is then macOS's own
# /etc/ssl/cert.pem (the daemon also loads it explicitly)
./Configure "$TARGET" no-shared no-tests no-docs \
	--prefix="$PREFIX" --libdir=lib --openssldir=/private/etc/ssl \
	"-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
make -j"$(sysctl -n hw.ncpu)" build_libs >/dev/null
make install_dev >/dev/null
echo "OpenSSL $VERSION ($ARCH, static, macOS >= $MACOSX_DEPLOYMENT_TARGET) in $PREFIX"
