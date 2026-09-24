#!/usr/bin/env bash
#
# Field-test harness for dpi-proxy packet mode (Linux only).
#
# Run this on the machine/network you actually want to validate
# against — not in a container or CI runner without real
# CAP_NET_ADMIN/CAP_NET_RAW. It builds packet mode, applies (and on
# exit, always removes) a real nftables rule, runs a PASS test and a
# SPLIT test against real network traffic, and reports PASS/FAIL/SKIP
# for each step. It never reports success it hasn't actually observed.
#
# Usage: ./scripts/field-test-linux.sh [split-test-domain]
#   (default split-test-domain: example.com)

set -u

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

SPLIT_DOMAIN="${1:-example.com}"
ENGINE_PID=""
STRATEGY_CONF_TMP=""
PCAP_TMP=""

pass() { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; }
skip() { printf '[SKIP] %s\n' "$1"; }
info() { printf '[info] %s\n' "$1"; }

# Every kill/kill -0 against $ENGINE_PID below goes through `sudo`:
# the engine runs as root (started via `sudo ... ./dpi-proxy-packet`),
# and a plain unprivileged `kill -TERM`/`kill -0` against a
# root-owned PID fails with EPERM — silently, once stderr is
# redirected, since that's indistinguishable here from "no such
# process". That previously meant this exact cleanup() trap could
# never actually stop a live engine on error or Ctrl-C. Demonstrated
# for real 2026-09-21: a manually-started engine kept running (and
# holding a live nftables/NFQUEUE rule) after `kill -TERM` reported
# nothing wrong.
cleanup() {
	info "cleaning up..."
	if [ -n "$ENGINE_PID" ] && sudo kill -0 "$ENGINE_PID" 2>/dev/null; then
		sudo kill -TERM "$ENGINE_PID" 2>/dev/null
		wait "$ENGINE_PID" 2>/dev/null
	fi
	# Best-effort, always attempted, regardless of what else failed —
	# never intentionally leave the table behind.
	sudo nft delete table inet dpi_proxy >/dev/null 2>&1
	[ -n "$STRATEGY_CONF_TMP" ] && rm -f "$STRATEGY_CONF_TMP"
	info "cleanup done (table inet dpi_proxy removed if it existed)"
}
trap cleanup EXIT INT TERM

echo "=== dpi-proxy field test (Linux packet mode) ==="
echo

# --- 1. required commands ---------------------------------------
echo "--- required commands ---"
for cmd in cc make curl sudo; do
	if command -v "$cmd" >/dev/null 2>&1; then
		pass "$cmd found"
	else
		fail "$cmd not found — cannot continue"
		exit 1
	fi
done
if command -v nft >/dev/null 2>&1; then
	pass "nft found"
else
	fail "nft not found — install the nftables package"
	exit 1
fi
if command -v tcpdump >/dev/null 2>&1; then
	pass "tcpdump found (will capture SPLIT evidence)"
	HAVE_TCPDUMP=1
else
	skip "tcpdump not found — SPLIT test will run without packet capture"
	HAVE_TCPDUMP=0
fi
echo

# --- 2. capabilities / privilege ---------------------------------
echo "--- capability check ---"
if sudo -n true 2>/dev/null; then
	pass "passwordless sudo available"
else
	info "sudo will prompt for a password when needed below"
fi
if sudo nft list tables >/dev/null 2>&1; then
	pass "nftables accessible via sudo"
else
	fail "cannot access nftables even via sudo — cannot continue"
	exit 1
fi
info "raw-socket capability will be reported for real by --capabilities below"
echo

# --- 3. build packet mode ----------------------------------------
echo "--- build ---"
if ! pkg-config --exists libnetfilter_queue 2>/dev/null; then
	fail "libnetfilter-queue-dev not installed — run:"
	echo "    sudo apt-get install -y libnetfilter-queue-dev nftables"
	exit 1
fi
pass "libnetfilter-queue-dev present"

if make packet-mode; then
	pass "make packet-mode succeeded"
else
	fail "make packet-mode failed — see build output above"
	exit 1
fi
echo

sudo ./dpi-proxy-packet --capabilities
echo

# --- 4. PASS test --------------------------------------------------
echo "--- PASS test ---"
echo "default = pass" > /tmp/dpi-proxy-field-test-strategy.conf
STRATEGY_CONF_TMP="/tmp/dpi-proxy-field-test-strategy.conf"

sudo DPI_PROXY_STRATEGY_CONF="$STRATEGY_CONF_TMP" DPI_PROXY_LOG_LEVEL=info \
	./dpi-proxy-packet > /tmp/dpi-proxy-field-test-pass.log 2>&1 &
ENGINE_PID=$!
sleep 1

if ! sudo kill -0 "$ENGINE_PID" 2>/dev/null; then
	fail "engine exited immediately — see /tmp/dpi-proxy-field-test-pass.log"
	cat /tmp/dpi-proxy-field-test-pass.log
	exit 1
fi
pass "engine started (pid $ENGINE_PID)"

if sudo nft list table inet dpi_proxy >/dev/null 2>&1; then
	pass "nftables rule installed (table inet dpi_proxy exists)"
	echo "    $(sudo nft list table inet dpi_proxy | tr '\n' ' ')"
else
	fail "table inet dpi_proxy not found after startup"
fi

if curl -sI --max-time 8 http://example.com >/dev/null; then
	pass "HTTP request through PASS engine succeeded"
else
	fail "HTTP request failed while engine (PASS) was running"
fi
if curl -sI --max-time 8 https://example.com >/dev/null; then
	pass "HTTPS request through PASS engine succeeded"
else
	fail "HTTPS request failed while engine (PASS) was running"
fi

sleep 1
echo "    nftables counter after traffic:"
echo "    $(sudo nft list table inet dpi_proxy | grep -i counter || echo '(no counter line found)')"

if grep -q "verdict=accept" /tmp/dpi-proxy-field-test-pass.log 2>/dev/null; then
	pass "engine log shows verdict=accept (packets actually reached the callback)"
else
	info "no verdict=accept lines seen (log level may be too quiet, or no matching traffic was generated)"
fi

sudo kill -TERM "$ENGINE_PID" 2>/dev/null
wait "$ENGINE_PID" 2>/dev/null
ENGINE_PID=""
if sudo nft list table inet dpi_proxy >/dev/null 2>&1; then
	fail "table inet dpi_proxy still present after SIGTERM shutdown"
else
	pass "clean shutdown: table inet dpi_proxy removed after SIGTERM"
fi
echo

# --- 5. repeated start/stop ----------------------------------------
echo "--- repeated start/stop ---"
sudo DPI_PROXY_STRATEGY_CONF="$STRATEGY_CONF_TMP" ./dpi-proxy-packet \
	> /tmp/dpi-proxy-field-test-restart.log 2>&1 &
ENGINE_PID=$!
sleep 1
if sudo kill -0 "$ENGINE_PID" 2>/dev/null && sudo nft list table inet dpi_proxy >/dev/null 2>&1; then
	pass "second start succeeded cleanly (no stale-rule conflict)"
else
	fail "second start failed — possible stale state from a previous run"
fi
sudo kill -INT "$ENGINE_PID" 2>/dev/null
wait "$ENGINE_PID" 2>/dev/null
ENGINE_PID=""
if sudo nft list table inet dpi_proxy >/dev/null 2>&1; then
	fail "table inet dpi_proxy still present after SIGINT shutdown"
else
	pass "clean shutdown: table inet dpi_proxy removed after SIGINT"
fi
echo

# --- 6. SPLIT test ---------------------------------------------------
echo "--- SPLIT test (domain: $SPLIT_DOMAIN) ---"
echo "IMPORTANT: this is the least-tested part of the project. A bug in"
echo "the anti-loop mark could, in principle, cause repeated re-queueing."
echo "Watch this step; Ctrl-C triggers cleanup at any time."
echo

printf 'default = pass\n\n[domains]\n%s = split\n' "$SPLIT_DOMAIN" \
	> "$STRATEGY_CONF_TMP"

PCAP_TMP=""
if [ "$HAVE_TCPDUMP" = "1" ]; then
	PCAP_TMP="/tmp/dpi-proxy-field-test-split.pcap"
	# `timeout` wraps sudo (not the other way around): a NOPASSWD sudo
	# rule scoped to `tcpdump` only authorizes running tcpdump as root,
	# not an arbitrary command via `sudo timeout N <anything>` — the
	# latter is a root-shell escape (`sudo timeout 5 /bin/bash`) if
	# sudoers ever grants `timeout` itself NOPASSWD.
	timeout 15 sudo tcpdump -i any -w "$PCAP_TMP" \
		"tcp port 443 and host $SPLIT_DOMAIN" >/tmp/dpi-proxy-field-test-tcpdump.log 2>&1 &
	sleep 1
fi

sudo DPI_PROXY_STRATEGY_CONF="$STRATEGY_CONF_TMP" DPI_PROXY_LOG_LEVEL=debug \
	./dpi-proxy-packet > /tmp/dpi-proxy-field-test-split.log 2>&1 &
ENGINE_PID=$!
sleep 1

if ! sudo kill -0 "$ENGINE_PID" 2>/dev/null; then
	fail "engine exited immediately for SPLIT test — see /tmp/dpi-proxy-field-test-split.log"
	cat /tmp/dpi-proxy-field-test-split.log
else
	pass "engine started for SPLIT test (pid $ENGINE_PID)"

	# -4: SPLIT is only wired to the live verdict path for IPv4 (see
	# nfqueue_engine.c). On a dual-stack
	# host, curl would otherwise happily take the AAAA route and the
	# SPLIT code would never run at all — a false "not exercised"
	# result that looks like a bug but isn't one.
	if curl -4 -sI --max-time 8 "https://$SPLIT_DOMAIN" >/dev/null; then
		pass "HTTPS request to $SPLIT_DOMAIN completed (200/response received)"
	else
		fail "HTTPS request to $SPLIT_DOMAIN failed with SPLIT active — this"
		echo "     does NOT necessarily mean the split code is broken: some"
		echo "     servers/CDNs reject a split ClientHello outright. Try"
		echo "     another domain before concluding the implementation itself"
		echo "     is wrong. See /tmp/dpi-proxy-field-test-split.log for the"
		echo "     engine's own [split] log line."
	fi

	if grep -q "verdict=drop+split" /tmp/dpi-proxy-field-test-split.log 2>/dev/null; then
		pass "engine log shows verdict=drop+split (SPLIT path was actually taken)"
	else
		info "no verdict=drop+split line seen — SPLIT strategy was never applied"
		echo "     (check that $SPLIT_DOMAIN's ClientHello arrived as a single"
		echo "     packet, and that strategy.conf matched the domain)"
	fi

	sudo kill -TERM "$ENGINE_PID" 2>/dev/null
	wait "$ENGINE_PID" 2>/dev/null
	ENGINE_PID=""
fi

if [ "$HAVE_TCPDUMP" = "1" ]; then
	wait 2>/dev/null
	if [ -s "$PCAP_TMP" ]; then
		pass "packet capture saved: $PCAP_TMP"
		echo "    Inspect with: sudo tcpdump -r $PCAP_TMP -nn"
		echo "    Look for: the ClientHello as two TCP segments, the second"
		echo "    segment's seq == first segment's seq + first segment's"
		echo "    length, and no third copy of either half (a third copy"
		echo "    would mean the anti-loop mark isn't excluding injected"
		echo "    packets and they're being re-queued)."
	else
		skip "no capture data written (tcpdump may need more time, or no"
		echo "    matching traffic occurred)"
	fi
fi
echo

echo "=== field test complete ==="
echo "This script reports what it actually observed. It does not and"
echo "cannot tell you whether SPLIT defeats DPI on your specific ISP —"
echo "only whether the mechanism ran without corrupting traffic here."
