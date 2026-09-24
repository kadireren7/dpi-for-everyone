#!/usr/bin/env bash
#
# Removes everything scripts/install.sh installed — the transparent and
# packet services, binaries, control CLI, learned decisions, and the
# two nftables tables dpi-proxy owns (inet dpi_proxy_tp, inet
# dpi_proxy). No other firewall state is touched. Needs root.
#
# /etc/dpi-proxy (your manual rules) is kept unless --purge is given.

set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

SERVICES="dpi-proxy-transparent dpi-proxy-packet"
BINS="/usr/local/bin/dpi-proxy /usr/local/bin/dpi-proxy-packet /usr/local/bin/dpi-proxy-ctl"
UNIT_DIR="/etc/systemd/system"
CONF_DIR="/etc/dpi-proxy"
STATE_DIR="/var/lib/dpi-proxy"

log() { printf '[uninstall] %s\n' "$1"; }
err() { printf '[uninstall] ERROR: %s\n' "$1" >&2; }

if [ "$(id -u)" -ne 0 ]; then
	err "this uninstaller removes system-wide services and needs root."
	err "run: sudo $0"
	exit 1
fi

log "[1/4] Stopping and disabling services..."
for s in $SERVICES; do
	systemctl disable --now "$s" >/dev/null 2>&1 || true
	rm -f "$UNIT_DIR/$s.service"
done
systemctl daemon-reload

log "[2/4] Removing binaries..."
# shellcheck disable=SC2086
rm -f $BINS

log "[3/4] Removing dpi-proxy's own nftables tables (if left over)..."
for t in dpi_proxy_tp dpi_proxy; do
	if nft list table inet "$t" >/dev/null 2>&1; then
		nft delete table inet "$t"
		log "  removed table inet $t"
	fi
done

log "[4/4] Removing learned state..."
rm -rf "$STATE_DIR" /run/dpi-proxy

if [ "$PURGE" = 1 ]; then
	rm -rf "$CONF_DIR"
	log "removed $CONF_DIR"
fi

echo
log "dpi-proxy removed."
if [ -d "$CONF_DIR" ]; then
	echo "Manual rules kept at $CONF_DIR (remove with: sudo $0 --purge)"
fi
