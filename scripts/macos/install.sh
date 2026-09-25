#!/bin/sh
#
# dpi-proxy for macOS — transparent mode (Beta) installer.
#
#   sudo ./install.sh
#
# Run it from the extracted package folder. Installs
#   /usr/local/bin/dpi-proxy, /usr/local/bin/dpi-proxy-ctl
#   /Library/LaunchDaemons/io.github.kadireren7.dpi-proxy.plist
#   /usr/local/etc/dpi-proxy/strategy.conf  (kept if it exists)
# starts the service and checks DNS and HTTPS through it. If that check
# fails, the service is stopped and removed again (networking stays as
# it was) and the installer exits non-zero. Re-running it updates an
# existing installation. Nothing else on the system is changed: PF
# rules live only in dpi-proxy's own anchor while the service runs.
set -eu

LABEL="io.github.kadireren7.dpi-proxy"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
BIN_DIR="/usr/local/bin"
ETC_DIR="/usr/local/etc/dpi-proxy"
VAR_DIR="/usr/local/var/dpi-proxy"
STATUS_FILE="/var/run/dpi-proxy/transparent.status"
LOG_FILE="/var/log/dpi-proxy.log"
HERE="$(cd "$(dirname "$0")" && pwd)"

log() { printf '==> %s\n' "$1"; }
fail() { printf 'install.sh: ERROR: %s\n' "$1" >&2; }
die() { fail "$1"; exit 1; }

[ "$(uname -s)" = Darwin ] || die "this installer is for macOS"
[ "$(id -u)" -eq 0 ] || die "run it with sudo:  sudo ./install.sh"
for f in dpi-proxy dpi-proxy-ctl "$LABEL.plist"; do
	[ -f "$HERE/$f" ] || die "$f is missing next to install.sh (extract the whole package)"
done

# A package downloaded with a browser is quarantined; the binaries in it
# are ours to run.
xattr -dr com.apple.quarantine "$HERE" 2>/dev/null || true

log "[1/5] Checking the package..."
if ! "$HERE/dpi-proxy" --version >/dev/null 2>&1; then
	die "dpi-proxy does not run on this Mac ($(uname -m), macOS $(sw_vers -productVersion)); is this the package for this Mac's processor?"
fi
"$HERE/dpi-proxy" --capabilities | grep -q '^transparent_mode: supported' \
	|| die "this dpi-proxy binary was built without transparent mode"
echo "    $("$HERE/dpi-proxy" --version), macOS $(sw_vers -productVersion), $(uname -m)"
for p in tpws spoofdpi ciadpi byedpi; do
	if pgrep -x "$p" >/dev/null 2>&1; then
		echo "    WARNING: $p is running (another DPI tool). Stop it: the two interfere."
	fi
done

log "[2/5] Stopping a previous installation (if any)..."
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
	launchctl bootout "system/$LABEL" 2>/dev/null || true
	i=0
	while [ $i -lt 40 ] && launchctl print "system/$LABEL" >/dev/null 2>&1; do
		sleep 0.25
		i=$((i + 1))
	done
fi

log "[3/5] Installing files..."
# remember which parent directories we create, so uninstall.sh removes
# exactly those (and only if they are empty then)
created=""
for d in /usr/local /usr/local/bin /usr/local/etc /usr/local/var; do
	if [ ! -d "$d" ]; then
		mkdir -p "$d"
		chmod 755 "$d"
		created="$created $d"
	fi
done
mkdir -p "$ETC_DIR" "$VAR_DIR"
chmod 755 "$ETC_DIR" "$VAR_DIR"
if [ -n "$created" ]; then
	for d in $created; do echo "$d"; done >>"$VAR_DIR/created-dirs"
fi
install -m 755 -o root -g wheel "$HERE/dpi-proxy" "$BIN_DIR/dpi-proxy"
install -m 755 -o root -g wheel "$HERE/dpi-proxy-ctl" "$BIN_DIR/dpi-proxy-ctl"
if [ ! -f "$ETC_DIR/strategy.conf" ]; then
	cat >"$ETC_DIR/strategy.conf" <<'CONF'
# dpi-proxy manual rules. Transparent mode needs none: known-blocked
# hosts (Discord and a few others, built in) get the bypass straight
# away; any other host is tried directly first and learns a bypass only
# if it needs one. Stream strategies: pass | tlsrec | tlsrec-split
# After editing: sudo dpi-proxy-ctl reload
#
# [domains]
# example.com = tlsrec
default = pass
CONF
	chmod 644 "$ETC_DIR/strategy.conf"
fi
install -m 644 -o root -g wheel "$HERE/$LABEL.plist" "$PLIST"
plutil -lint "$PLIST" >/dev/null || die "$PLIST is not a valid property list"
echo "    $BIN_DIR/dpi-proxy, $BIN_DIR/dpi-proxy-ctl, $PLIST, $ETC_DIR/"

log "[4/5] Starting the service..."
rm -f "$STATUS_FILE"
launchctl enable "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST" || die "launchctl bootstrap failed"

log "[5/5] Checking health (DNS and HTTPS through the service)..."
field() { sed -n "s/^$1: //p" "$STATUS_FILE" 2>/dev/null | head -n 1; }
healthy=0
problem="the service did not report \"engine: running\" within 20 s"
i=0
while [ $i -lt 40 ]; do
	if [ "$(field engine)" = running ] && [ "$(field pf_anchor)" = "com.apple/dpi-proxy loaded" ]; then
		healthy=1
		break
	fi
	sleep 0.5
	i=$((i + 1))
done
if [ $healthy -eq 1 ]; then
	dscacheutil -flushcache 2>/dev/null || true
	killall -HUP mDNSResponder 2>/dev/null || true
	sleep 1
	if ! dscacheutil -q host -a name example.com | grep -q '^ip_address:'; then
		healthy=0
		problem="name resolution (example.com) through the service failed"
	elif ! code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 https://example.com/ 2>&1)" \
		|| ! echo "$code" | grep -Eq '^[23][0-9][0-9]$'; then
		healthy=0
		problem="HTTPS check (https://example.com/) through the service failed: $code"
	fi
fi
if [ $healthy -ne 1 ]; then
	fail "$problem"
	echo '--- last log lines ---' >&2
	tail -n 25 "$LOG_FILE" 2>/dev/null >&2 || true
	[ -s /var/log/dpi-proxy.stderr.log ] && tail -n 10 /var/log/dpi-proxy.stderr.log >&2
	fail "stopping and unregistering the service again (fail-open: networking is unchanged)"
	launchctl bootout "system/$LABEL" 2>/dev/null || true
	rm -f "$PLIST"
	fail "please send the output above; remove the rest with: sudo ./uninstall.sh"
	exit 4
fi

echo
log "Done. dpi-proxy is running and starts automatically at boot."
echo "    HTTPS and DNS from all applications now go through the automatic"
echo "    bypass; no proxy settings, no DNS changes, no per-app setup."
echo
echo "    Status:     dpi-proxy-ctl status"
echo "    Problems:   dpi-proxy-ctl diagnose discord.com   and   dpi-proxy-ctl logs"
echo "    Stop:       sudo dpi-proxy-ctl stop     (networking keeps working, unbypassed)"
echo "    Uninstall:  sudo ./uninstall.sh         (in this folder)"
c="$(field conflict)"
if [ -n "$c" ] && [ "$c" != none ]; then
	echo
	echo "    WARNING: $c — stop it, the two tools interfere."
fi
