#!/usr/bin/env bash
#
# End-to-end test of Linux transparent mode on a real machine (CI:
# GitHub's ubuntu runner, sudo). Installs with scripts/install.sh, then
# checks the whole lifecycle; exits non-zero on the first failure.
# It uninstalls at the end — don't run it where you want to keep an
# installation.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
STATUS=/run/dpi-proxy/transparent.status
CONF=/etc/dpi-proxy/strategy.conf
step=0

stepn() { step=$((step + 1)); printf '\n=== [%d] %s\n' "$step" "$1"; }
pass() { printf 'PASS: %s\n' "$1"; }
die() {
	printf 'FAIL: %s\n' "$1"
	journalctl -u dpi-proxy-transparent --no-pager -n 60 || true
	cat "$STATUS" 2>/dev/null || true
	exit 1
}
field() { sed -n "s/^$1: //p" "$STATUS" | head -n 1; }
wait_status() { sleep 11; }	# status is rewritten every 10 s
fetch() { curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$1" 2>&1 || true; }
ok() { [[ "$1" =~ ^[23][0-9][0-9]$ ]]; }

stepn install
sudo "$ROOT/scripts/install.sh" || die "install.sh failed"
systemctl is-active --quiet dpi-proxy-transparent || die "service not active"
pass "installed; installer health check (DNS + HTTPS through it) passed"

stepn "normal HTTPS works and is intercepted"
for u in https://example.com/ https://www.wikipedia.org/ https://github.com/; do
	c="$(fetch "$u")"; ok "$c" || die "$u -> '$c'"
done
wait_status
[ "$(field flows)" -ge 3 ] || die "flows=$(field flows)"
[ "$(field failures)" -eq 0 ] || die "failures=$(field failures)"
pass "flows=$(field flows) direct=$(field direct) failures=0"

stepn "DNS goes through the forwarder (DoH)"
sudo resolvectl flush-caches 2>/dev/null || true
getent ahostsv4 example.net >/dev/null || die "resolution failed"
wait_status
[ "$(field dns_intercept)" = doh ] || die "dns_intercept=$(field dns_intercept)"
[ "$(field dns_queries)" -ge 1 ] || die "no DNS query reached the forwarder"
pass "dns_intercept=doh dns_queries=$(field dns_queries)"

stepn "no redirect loop"
before="$(field flows)"
for _ in 1 2 3 4 5; do fetch https://example.com/ >/dev/null; done
wait_status
delta=$(( $(field flows) - before ))
{ [ "$delta" -ge 5 ] && [ "$delta" -le 60 ]; } || die "5 requests -> $delta flows"
pass "5 requests -> $delta flows"

stepn "bypass path: forced tlsrec rule for example.com"
printf '\n[domains]\nexample.com = tlsrec\n' | sudo tee -a "$CONF" >/dev/null
sudo systemctl restart dpi-proxy-transparent
sleep 3
c="$(fetch https://example.com/)"; ok "$c" || die "example.com with tlsrec -> '$c'"
wait_status
[ "$(field bypassed)" -ge 1 ] || die "bypassed=$(field bypassed)"
pass "example.com via tlsrec: HTTP $c; bypassed=$(field bypassed)"

stepn "stop = ordinary networking"
sudo systemctl stop dpi-proxy-transparent
sudo nft list table inet dpi_proxy_tp >/dev/null 2>&1 && die "table left behind"
c="$(fetch https://example.com/)"; ok "$c" || die "stopped -> '$c'"
pass "stopped: table gone, HTTPS $c"

stepn "crash = fail-open, then automatic restart"
sudo systemctl start dpi-proxy-transparent
sleep 3
sudo systemctl kill -s KILL dpi-proxy-transparent
sleep 1
c="$(fetch https://example.com/)"; ok "$c" || die "right after a crash -> '$c'"
for _ in $(seq 1 20); do systemctl is-active --quiet dpi-proxy-transparent && break; sleep 1; done
systemctl is-active --quiet dpi-proxy-transparent || die "not restarted"
sleep 3
c="$(fetch https://example.com/)"; ok "$c" || die "after restart -> '$c'"
pass "killed: fail-open, restarted, HTTPS $c"

stepn "dpictl"
dpictl status
dpictl status --verbose
dpictl diagnose example.com
dpictl version | grep -q . || die "dpictl version printed nothing"
dpictl doctor || die "dpictl doctor reported a failure while the service is healthy"
bundle="$(mktemp -u).tar.gz"
dpictl support-bundle "$bundle" || die "support-bundle failed"
[ -s "$bundle" ] || die "support-bundle produced an empty/missing archive"
tar -tzf "$bundle" | grep -q '^version.txt$' || die "support-bundle archive missing version.txt"
bundle_dir="$(mktemp -d)"
tar -xzf "$bundle" -C "$bundle_dir"
if grep -rl "$HOME" "$bundle_dir" >/dev/null 2>&1; then
	die "support-bundle leaked \$HOME ($HOME) into the archive"
fi
if grep -rlE '(^|[^a-zA-Z0-9_])'"$USER"'([^a-zA-Z0-9_]|$)' "$bundle_dir" >/dev/null 2>&1; then
	die "support-bundle leaked the username ($USER) into the archive"
fi
[ -f "$bundle_dir/dns-history-summary.txt" ] || die "support-bundle missing dns-history-summary.txt"
grep -q "raw per-domain/per-IP records are not included" "$bundle_dir/dns-history-summary.txt" \
	|| die "support-bundle included raw DNS decision history instead of a summary"
rm -rf "$bundle_dir" "$bundle"
pass "dpictl status/doctor/support-bundle/version ran; archive redaction verified"

stepn "dpi-proxy-ctl (compatibility alias)"
dpi-proxy-ctl status
dpi-proxy-ctl diagnose example.com
pass "alias still works"

stepn "uninstall cleans only our own state"
sudo "$ROOT/scripts/uninstall.sh" --purge
systemctl list-unit-files | grep -q dpi-proxy-transparent && die "unit still present"
sudo nft list table inet dpi_proxy_tp >/dev/null 2>&1 && die "table still present"
c="$(fetch https://example.com/)"; ok "$c" || die "after uninstall -> '$c'"
pass "uninstalled; HTTPS $c"

printf '\nALL LINUX E2E CHECKS PASSED\n'
