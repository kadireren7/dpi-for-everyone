#!/bin/sh
#
# dpi-proxy for macOS — uninstaller.
#
#   sudo ./uninstall.sh
#
# Stops the service and removes everything install.sh put on the
# system: the launchd job, the binaries, the settings, learned
# decisions, logs, dpi-proxy's PF anchor and its PF enable reference.
# Nothing else is touched: other PF anchors, the main ruleset,
# /etc/pf.conf and other programs' PF references stay as they are.
set -u

LABEL="io.github.kadireren7.dpi-proxy"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
ANCHOR="com.apple/dpi-proxy"
VAR_DIR="/usr/local/var/dpi-proxy"
RUN_DIR="/var/run/dpi-proxy"

log() { printf '==> %s\n' "$1"; }

[ "$(uname -s)" = Darwin ] || { echo "uninstall.sh: this is for macOS" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "uninstall.sh: run it with sudo:  sudo ./uninstall.sh" >&2; exit 1; }

log "Stopping the service..."
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
	launchctl bootout "system/$LABEL" 2>/dev/null || true
	i=0
	while [ $i -lt 40 ] && launchctl print "system/$LABEL" >/dev/null 2>&1; do
		sleep 0.25
		i=$((i + 1))
	done
fi
launchctl disable "system/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
# anything of ours still running (e.g. a watchdog whose daemon was
# killed): it removes our rules on SIGTERM
for pid in $(pgrep -f '^/usr/local/bin/dpi-proxy' 2>/dev/null); do
	kill "$pid" 2>/dev/null || true
done
sleep 1
for pid in $(pgrep -f '^/usr/local/bin/dpi-proxy' 2>/dev/null); do
	kill -9 "$pid" 2>/dev/null || true
done

log "Removing dpi-proxy's PF rules (anchor $ANCHOR only)..."
pfctl -a "$ANCHOR" -F nat >/dev/null 2>&1 || true
pfctl -a "$ANCHOR" -F rules >/dev/null 2>&1 || true
pfctl -a "$ANCHOR" -F Tables >/dev/null 2>&1 || true
# the PF enable reference of a daemon that could not release it itself
if [ -f "$RUN_DIR/pf.token" ]; then
	token="$(tr -cd '0-9' <"$RUN_DIR/pf.token")"
	[ -n "$token" ] && pfctl -X "$token" >/dev/null 2>&1 || true
fi

log "Removing files..."
rm -f /usr/local/bin/dpi-proxy /usr/local/bin/dpi-proxy-ctl
created=""
[ -f "$VAR_DIR/created-dirs" ] && created="$(sort -r -u "$VAR_DIR/created-dirs")"
rm -rf /usr/local/etc/dpi-proxy "$VAR_DIR" "$RUN_DIR"
rm -f /var/log/dpi-proxy.log /var/log/dpi-proxy.log.1 /var/log/dpi-proxy.stderr.log
# parent directories install.sh had to create, if nothing else uses them
for d in $created; do
	rmdir "$d" 2>/dev/null || true
done

# answers cached while the service ran came from the trusted resolvers;
# start fresh with the network's own
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true

left=""
[ -e "$PLIST" ] && left="$left $PLIST"
[ -e /usr/local/bin/dpi-proxy ] && left="$left /usr/local/bin/dpi-proxy"
[ -e /usr/local/bin/dpi-proxy-ctl ] && left="$left /usr/local/bin/dpi-proxy-ctl"
[ -e /usr/local/etc/dpi-proxy ] && left="$left /usr/local/etc/dpi-proxy"
[ -e "$VAR_DIR" ] && left="$left $VAR_DIR"
launchctl print "system/$LABEL" >/dev/null 2>&1 && left="$left launchd-job"
pfctl -a "$ANCHOR" -s nat 2>/dev/null | grep -q . && left="$left pf-anchor"
pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -q . && left="$left pf-anchor"
pgrep -f '^/usr/local/bin/dpi-proxy' >/dev/null 2>&1 && left="$left process"
if [ -n "$left" ]; then
	echo "uninstall.sh: could not remove:$left" >&2
	exit 1
fi
log "dpi-proxy is uninstalled; networking is back to normal."
