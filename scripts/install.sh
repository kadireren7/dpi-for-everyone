#!/usr/bin/env bash
#
# Installs dpi-proxy on Linux: transparent mode as a system service —
# after this, HTTPS from every application goes through the automatic
# DPI bypass with no proxy settings anywhere. Needs root (sudo).
#
#   sudo ./scripts/install.sh            install or upgrade (idempotent)
#   sudo ./scripts/install.sh --packet   also install packet mode
#                                        (dpi-proxy-packet; needs
#                                        libnetfilter-queue-dev), not
#                                        started automatically
#
# Everything installed is owned by dpi-proxy; scripts/uninstall.sh
# removes exactly that and nothing else.

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

TP_SERVICE="dpi-proxy-transparent"
PACKET_SERVICE="dpi-proxy-packet"
TP_TABLE="dpi_proxy_tp"
BIN_DEST="/usr/local/bin/dpi-proxy"
PACKET_BIN_DEST="/usr/local/bin/dpi-proxy-packet"
DPICTL_DEST="/usr/local/bin/dpictl"
CTL_DEST="/usr/local/bin/dpi-proxy-ctl"
UNIT_DIR="/etc/systemd/system"
CONF_DIR="/etc/dpi-proxy"
CONF_DEST="$CONF_DIR/strategy.conf"
STATUS_FILE="/run/dpi-proxy/transparent.status"

WITH_PACKET=0
for arg in "$@"; do
	case "$arg" in
	--packet) WITH_PACKET=1 ;;
	-h | --help)
		sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		printf '[install] unknown option: %s\n' "$arg" >&2
		exit 1
		;;
	esac
done

log() { printf '[install] %s\n' "$1"; }
err() { printf '[install] ERROR: %s\n' "$1" >&2; }

if [ "$(id -u)" -ne 0 ]; then
	err "this installer sets up a system-wide service and needs root."
	err "run: sudo $0"
	exit 1
fi

# If anything below fails, leave the machine fail-open: our service
# stopped and our nftables table gone. Files already copied stay (a
# re-run overwrites them).
INSTALL_OK=0
cleanup_on_failure() {
	if [ "$INSTALL_OK" -ne 1 ]; then
		err "install failed — stopping $TP_SERVICE and removing its nftables table"
		systemctl stop "$TP_SERVICE" >/dev/null 2>&1 || true
		nft delete table inet "$TP_TABLE" >/dev/null 2>&1 || true
	fi
}
trap cleanup_on_failure EXIT

# Build as the invoking (non-root) user, so build artifacts in the repo
# stay owned by them.
BUILD_USER="${SUDO_USER:-root}"
run_as_build_user() {
	if [ "$BUILD_USER" != "root" ]; then
		sudo -u "$BUILD_USER" -- "$@"
	else
		"$@"
	fi
}

log "[1/7] Checking dependencies..."
missing=""
for tool in cc make nft systemctl openssl; do
	command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
	err "missing:$missing"
	err "on Debian/Ubuntu: sudo apt-get install -y build-essential nftables openssl"
	exit 2
fi
# Transparent mode's DNS-over-HTTPS resolver links OpenSSL.
if [ ! -f /usr/include/openssl/ssl.h ] && ! pkg-config --exists openssl 2>/dev/null; then
	if command -v apt-get >/dev/null 2>&1; then
		log "  installing libssl-dev (OpenSSL headers, build-time only)..."
		DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev >/dev/null \
			|| { err "could not install libssl-dev: sudo apt-get install -y libssl-dev"; exit 2; }
	else
		err "missing OpenSSL development headers (libssl-dev / openssl-devel)"
		exit 2
	fi
fi
if [ "$WITH_PACKET" = 1 ] && ! pkg-config --exists libnetfilter_queue 2>/dev/null; then
	err "--packet needs libnetfilter-queue-dev: sudo apt-get install -y libnetfilter-queue-dev"
	exit 2
fi
log "  OK"

log "[2/7] Building (as user: $BUILD_USER)..."
cd "$PROJECT_ROOT"
if [ "$WITH_PACKET" = 1 ]; then
	# packet-mode starts with `make clean`, so it goes first
	run_as_build_user make packet-mode || { err "packet-mode build failed"; exit 3; }
else
	# always from clean: objects from an older tree may predate header
	# dependency tracking and would otherwise be linked stale
	run_as_build_user make clean >/dev/null
fi
run_as_build_user make all || { err "build failed — see output above"; exit 3; }
"$PROJECT_ROOT/dpi-proxy" --capabilities | grep -q '^transparent_mode: supported' \
	|| { err "built binary has no transparent mode"; exit 3; }

log "[3/7] Stopping running dpi-proxy services for a clean (re)install..."
systemctl stop "$TP_SERVICE" >/dev/null 2>&1 || true
# Two engines on TCP/443 at once is never intended: transparent mode
# replaces packet mode as the automatic engine. Packet mode stays
# installed and can be started by hand (dpi-proxy-ctl packet start).
if systemctl is-enabled --quiet "$PACKET_SERVICE" 2>/dev/null \
	|| systemctl is-active --quiet "$PACKET_SERVICE" 2>/dev/null; then
	log "  stopping and disabling $PACKET_SERVICE (transparent mode replaces it)"
	systemctl disable --now "$PACKET_SERVICE" >/dev/null 2>&1 || true
fi

# Another transparent DPI tool (e.g. the dpi-bypass service) running at
# the same time intercepts our upstream connections and DNS and breaks
# both. We never touch it; the user decides which one runs.
OTHER_ACTIVE=0
if nft list table ip dpibypass >/dev/null 2>&1 \
	|| systemctl is-active --quiet dpi-bypass 2>/dev/null; then
	OTHER_ACTIVE=1
	echo
	err "the dpi-bypass service is active. Two transparent DPI tools at once"
	err "proxy each other's traffic and break connections. dpi-proxy is"
	err "installed anyway, but stop one of them:"
	err "  sudo systemctl stop dpi-bypass            (until reboot)"
	err "  sudo systemctl disable --now dpi-bypass   (permanently)"
	echo
fi

log "[4/7] Installing binaries to /usr/local/bin..."
install -m 0755 "$PROJECT_ROOT/dpi-proxy" "$BIN_DEST"
install -m 0755 "$PROJECT_ROOT/scripts/dpictl" "$DPICTL_DEST"
install -m 0755 "$PROJECT_ROOT/scripts/dpi-proxy-ctl" "$CTL_DEST"
if [ "$WITH_PACKET" = 1 ]; then
	install -m 0755 "$PROJECT_ROOT/dpi-proxy-packet" "$PACKET_BIN_DEST"
fi

log "[5/7] Config..."
mkdir -p "$CONF_DIR"
if [ -f "$CONF_DEST" ]; then
	log "  keeping existing $CONF_DEST"
else
	cat > "$CONF_DEST" <<'EOF'
# dpi-proxy manual rules. Transparent mode needs none: known-blocked
# hosts (Discord and a few others, built in) get the bypass straight
# away; any other host is tried directly first and learns a bypass only
# if it needs one. A rule here overrides that for exactly the named host
# (and its subdomains). Stream strategies: pass | tlsrec | tlsrec-split
#
# [domains]
# example.com = tlsrec
default = pass
EOF
	log "  wrote $CONF_DEST (no manual rules — everything automatic)"
fi

log "[6/7] Installing systemd unit(s)..."
install -m 0644 "$PROJECT_ROOT/systemd/$TP_SERVICE.service" "$UNIT_DIR/$TP_SERVICE.service"
if [ "$WITH_PACKET" = 1 ]; then
	install -m 0644 "$PROJECT_ROOT/systemd/$PACKET_SERVICE.service" "$UNIT_DIR/$PACKET_SERVICE.service"
fi
systemctl daemon-reload
systemctl enable "$TP_SERVICE" >/dev/null

log "[7/7] Starting $TP_SERVICE and checking health..."
rm -f "$STATUS_FILE"
systemctl start "$TP_SERVICE" || { err "start failed: journalctl -u $TP_SERVICE -n 50"; exit 4; }
healthy=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
	if systemctl is-active --quiet "$TP_SERVICE" \
		&& nft list set inet "$TP_TABLE" alive 2>/dev/null | grep -q '443' \
		&& grep -q '^engine: running' "$STATUS_FILE" 2>/dev/null; then
		healthy=1
		break
	fi
	sleep 0.5
done
if [ "$healthy" != 1 ]; then
	err "service is not healthy. Check: journalctl -u $TP_SERVICE -n 50"
	exit 4
fi
# answers cached before DNS was intercepted may be block-page addresses
command -v resolvectl >/dev/null 2>&1 && resolvectl flush-caches >/dev/null 2>&1 || true
if grep -q '^dns_intercept: off' "$STATUS_FILE" 2>/dev/null; then
	log "  note: DNS is not intercepted (see journalctl -u $TP_SERVICE)"
elif ! getent ahostsv4 example.com >/dev/null 2>&1; then
	err "name resolution through the engine's DNS forwarder failed; stopping it"
	exit 4
fi
if ! curl -sS -o /dev/null --max-time 15 https://example.com/ 2>/dev/null \
	&& ! openssl s_client -connect example.com:443 -servername example.com \
		-verify_hostname example.com </dev/null 2>/dev/null \
		| grep -q 'Verify return code: 0 (ok)'; then
	err "HTTPS check through the engine failed (example.com); stopping it"
	exit 4
fi

INSTALL_OK=1
echo
log "Done. Transparent mode is running and enabled at boot."
echo
echo "  HTTPS from all applications now goes through the automatic bypass,"
echo "  and DNS is answered over DNS-over-HTTPS (no poisoned answers);"
echo "  no browser/app proxy settings and no DNS changes are needed."
if [ "$OTHER_ACTIVE" = 1 ]; then
	echo
	echo "  WARNING: dpi-bypass is still active — stop it (see above), or the"
	echo "  two will interfere."
fi
echo
echo "  Status:     dpictl status               (sudo for interception counters)"
echo "  Doctor:     dpictl doctor                (health checks)"
echo "  Logs:       dpictl logs"
echo "  Stop:       sudo dpictl stop             (internet keeps working, unbypassed)"
echo "  Uninstall:  sudo ./scripts/uninstall.sh"
echo "  Config:     $CONF_DEST (optional manual rules)"
echo "  (dpi-proxy-ctl still works as an alias for dpictl)"
