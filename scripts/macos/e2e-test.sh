#!/bin/sh
#
# End-to-end test of macOS transparent mode on a real Mac (CI: GitHub's
# macOS runners; needs passwordless sudo). Installs from a package
# folder exactly as a user would, then checks the whole lifecycle:
# PF interception, DNS, the bypass path, loops, restart, stop, crash
# and hang fail-open, launchd restart, uninstall leaving nothing
# behind, clean reinstall. Exits non-zero on the first failure.
#
#   ./e2e-test.sh <package-dir>
#
# It uninstalls at the end: don't run it on a Mac whose dpi-proxy
# installation you want to keep.
set -u

PKG="$(cd "${1:?usage: e2e-test.sh <package-dir>}" && pwd)"
LABEL="io.github.kadireren7.dpi-proxy"
ANCHOR="com.apple/dpi-proxy"
STATUS=/var/run/dpi-proxy/transparent.status
CONF=/usr/local/etc/dpi-proxy/strategy.conf
LOG=/var/log/dpi-proxy.log
step=0

stepn() { step=$((step + 1)); printf '\n=== [%d] %s\n' "$step" "$1"; }
pass() { printf 'PASS: %s\n' "$1"; }
note() { printf 'NOTE: %s\n' "$1"; }
die() {
	printf 'FAIL: %s\n' "$1"
	echo '--- log ---'; sudo tail -n 80 "$LOG" 2>/dev/null
	echo '--- stderr log ---'; sudo tail -n 20 /var/log/dpi-proxy.stderr.log 2>/dev/null
	echo '--- status ---'; cat "$STATUS" 2>/dev/null
	echo '--- anchor ---'; sudo pfctl -a "$ANCHOR" -s nat 2>/dev/null; sudo pfctl -a "$ANCHOR" -s rules 2>/dev/null
	echo '--- pf info ---'; sudo pfctl -s info 2>/dev/null | head -n 3
	exit 1
}
field() { sed -n "s/^$1: //p" "$STATUS" 2>/dev/null | head -n 1; }
# the status file is rewritten on every heartbeat (10 s)
wait_status() { sleep 11; }
fetch() { curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$1" 2>&1 || true; }
ok() { echo "$1" | grep -Eq '^[23][0-9][0-9]$'; }
daemon_pid() {
	launchctl print "system/$LABEL" 2>/dev/null \
		| sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' | head -n 1
}
anchor_rules() {
	{ sudo pfctl -a "$ANCHOR" -s nat 2>/dev/null; sudo pfctl -a "$ANCHOR" -s rules 2>/dev/null; } \
		| grep -c -e '^rdr' -e 'route-to' -e '^block'
}
wait_running() {
	i=0
	while [ $i -lt 60 ]; do
		p="$(daemon_pid)"
		if [ -n "$p" ] && [ "$(field pid)" = "$p" ] && [ "$(field engine)" = running ]; then
			return 0
		fi
		sleep 0.5
		i=$((i + 1))
	done
	return 1
}
pf_state() {
	# PF on/off, the main ruleset and nat/rdr rules, the other anchors:
	# what must be exactly the same before install and after stop /
	# uninstall. (Our anchor's *name* is left out: once created, macOS
	# keeps an anchor name registered, empty, until reboot — no pfctl
	# operation removes it, not even -F all. anchor_empty checks that
	# nothing is in it.)
	sudo pfctl -s info 2>/dev/null | sed -n 's/^Status: \([A-Za-z]*\).*/\1/p'
	sudo pfctl -s rules 2>/dev/null
	sudo pfctl -s nat 2>/dev/null
	sudo pfctl -a com.apple -s Anchors 2>/dev/null | grep -v -x '  com.apple/dpi-proxy'
}
anchor_empty() {
	[ -z "$( { sudo pfctl -a "$ANCHOR" -s nat; sudo pfctl -a "$ANCHOR" -s rules;
		sudo pfctl -a "$ANCHOR" -s Tables; } 2>/dev/null | grep -v -e '^No ALTQ' -e '^ALTQ')" ]
}

stepn "before: PF state and direct networking"
sudo pfctl -s info 2>/dev/null | head -n 2
sudo pfctl -s References 2>/dev/null
pf_state >/tmp/dpi-e2e-pf-before.txt
cat /tmp/dpi-e2e-pf-before.txt
c="$(fetch https://example.com/)"; ok "$c" || die "no direct HTTPS before installing: '$c'"
v6=0
if curl -6 -sS -o /dev/null --max-time 8 https://www.google.com/ 2>/dev/null; then v6=1; fi
note "this machine has IPv6 internet: $([ $v6 -eq 1 ] && echo yes || echo no)"
t0="$(date +%s)"
curl -sS -o /dev/null --max-time 60 -w 'direct download: %{size_download} bytes in %{time_total}s (%{speed_download} B/s)\n' \
	'https://speed.cloudflare.com/__down?bytes=50000000' || true
pass "direct HTTPS $c"

stepn "the generated PF anchor parses (pfctl -n, nothing loaded)"
"$PKG/dpi-proxy" --print-pf-rules | sudo pfctl -a "$ANCHOR-ci-parse" -n -f - || die "pfctl rejects the ruleset"
pass "pfctl accepts the ruleset"

stepn "install (sudo ./install.sh from the package, as a user would)"
( cd "$PKG" && sudo ./install.sh ) || die "install.sh failed"
wait_running || die "service not running after install"
[ -f "/Library/LaunchDaemons/$LABEL.plist" ] || die "plist missing"
[ -x /usr/local/bin/dpi-proxy ] && [ -x /usr/local/bin/dpictl ] && [ -x /usr/local/bin/dpi-proxy-ctl ] \
	|| die "binaries missing"
command -v dpictl >/dev/null || die "dpictl is not on the PATH"
command -v dpi-proxy-ctl >/dev/null || die "dpi-proxy-ctl is not on the PATH"
pass "installed; launchd job running (pid $(daemon_pid)); installer health check passed"

stepn "PF: enabled, our anchor loaded, main ruleset untouched, watchdog up"
[ "$(sudo pfctl -s info | sed -n 's/^Status: \([A-Za-z]*\).*/\1/p')" = Enabled ] || die "PF not enabled"
sudo pfctl -a "$ANCHOR" -s nat
sudo pfctl -a "$ANCHOR" -s rules
n="$(anchor_rules)"
[ "$n" -ge 4 ] || die "only $n rules in $ANCHOR"
sudo pfctl -s rules 2>/dev/null >/tmp/dpi-e2e-main-rules.txt
sudo pfctl -s nat 2>/dev/null >/tmp/dpi-e2e-main-nat.txt
sed -n '2,$p' /tmp/dpi-e2e-pf-before.txt | grep -v -e 'dpi-proxy' >/tmp/dpi-e2e-a.txt
{ cat /tmp/dpi-e2e-main-rules.txt /tmp/dpi-e2e-main-nat.txt; sudo pfctl -a com.apple -s Anchors 2>/dev/null; } \
	| grep -v -e 'dpi-proxy' >/tmp/dpi-e2e-b.txt
diff /tmp/dpi-e2e-a.txt /tmp/dpi-e2e-b.txt || die "the main ruleset or other anchors changed"
wd="$(pgrep -f -- '--pf-watchdog' | head -n 1)"
[ -n "$wd" ] || die "no watchdog process"
[ "$(field pf_watchdog)" = "running (pid $wd)" ] || die "status says watchdog '$(field pf_watchdog)'"
sudo pfctl -s References 2>/dev/null
pass "$n rules in $ANCHOR; main ruleset unchanged; watchdog pid $wd"

stepn "normal HTTPS works and is intercepted"
for u in https://example.com/ https://www.wikipedia.org/ https://github.com/ https://www.apple.com/; do
	c="$(fetch "$u")"; ok "$c" || die "$u -> '$c'"
done
wait_status
[ "$(field flows)" -ge 4 ] || die "expected >= 4 intercepted flows, status says $(field flows)"
[ "$(field failures)" -eq 0 ] || die "failures=$(field failures)"
pass "4 sites OK; flows=$(field flows) direct=$(field direct) failures=0"

stepn "the original destination is recovered (DIOCNATLOOK) for a literal IP"
ip="$(dig +short +time=3 +tries=1 A example.com | grep -E '^[0-9.]+$' | head -n 1)"
[ -n "$ip" ] || die "could not resolve example.com"
before="$(field flows)"
c="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 --resolve "example.com:443:$ip" https://example.com/ 2>&1)"
ok "$c" || die "https://example.com via $ip -> '$c'"
wait_status
[ "$(field flows)" -gt "$before" ] || die "the connection to $ip was not intercepted"
pass "connection to $ip:443 went through the proxy and reached the right server (HTTP $c)"

stepn "DNS goes through the forwarder (DoH), local names do not"
dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null; sleep 1
q0="$(field dns_queries)"
dscacheutil -q host -a name example.net | grep -q '^ip_address:' || die "system resolution of example.net failed"
dig +time=3 +tries=1 example.org | grep -q 'status: NOERROR' || die "dig example.org failed"
wait_status
[ "$(field dns_intercept)" = doh ] || die "dns_intercept=$(field dns_intercept)"
[ "$(field dns_queries)" -gt "$q0" ] || die "no DNS query reached the forwarder"
dig +time=3 +tries=1 "dpi-e2e-$$.invalid" | grep -q 'status: NXDOMAIN' || die "a nonexistent name did not get NXDOMAIN"
if dig +time=5 +tries=1 "dpi-e2e-host-$$.lan" >/tmp/dpi-e2e-lan.txt 2>&1; then
	note "local name (.lan) -> $(sed -n 's/.*status: \([A-Z]*\).*/\1/p' /tmp/dpi-e2e-lan.txt) from the network's own resolver"
fi
ping -c 1 -t 2 localhost >/dev/null 2>&1 || die "localhost does not resolve"
lh="$(scutil --get LocalHostName 2>/dev/null).local"
if dscacheutil -q host -a name "$lh" | grep -q '^ip_address:'; then
	note "mDNS/Bonjour name $lh still resolves"
else
	note "mDNS name $lh did not resolve (runner has no Bonjour responder on the LAN side; not an error)"
fi
pass "dns_intercept=doh dns_queries=$(field dns_queries) dns_failures=$(field dns_failures); localhost OK"

stepn "QUIC fallback: a known-blocked name's addresses go into the QUIC-reject table"
dig +time=5 +tries=1 A discord.com >/dev/null 2>&1
sleep 1
sudo pfctl -a "$ANCHOR" -t dpi_quic4 -T show 2>/dev/null | tee /tmp/dpi-e2e-quic.txt
[ -s /tmp/dpi-e2e-quic.txt ] || die "no addresses in dpi_quic4 after resolving discord.com"
qip="$(head -n 1 /tmp/dpi-e2e-quic.txt | tr -d ' ')"
if python3 - "$qip" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.connect((sys.argv[1], 443))
s.send(b"\xc0" + b"\x00" * 1199)
try:
    s.recv(100)
except ConnectionRefusedError:
    sys.exit(0)
except Exception:
    pass
try:
    s.send(b"\xc0" + b"\x00" * 1199)
except ConnectionRefusedError:
    sys.exit(0)
sys.exit(1)
PY
then
	pass "UDP/443 to $qip is refused at once (applications fall back to TCP)"
else
	note "UDP/443 refusal to $qip not observable from python here; table populated"
	pass "QUIC-reject table populated"
fi

stepn "IPv6"
if [ $v6 -eq 1 ]; then
	before="$(field flows)"
	c="$(curl -6 -sS -o /dev/null -w '%{http_code}' --max-time 20 https://www.google.com/ 2>&1)"
	ok "$c" || die "IPv6 HTTPS through the proxy -> '$c'"
	wait_status
	[ "$(field flows)" -gt "$before" ] || die "IPv6 connection was not intercepted"
	pass "IPv6 HTTPS intercepted (HTTP $c)"
else
	note "no IPv6 internet on this machine: IPv6 interception not exercised"
fi

stepn "no redirect loop"
before="$(field flows)"
for _ in 1 2 3 4 5; do fetch https://example.com/ >/dev/null; done
wait_status
delta=$(( $(field flows) - before ))
{ [ "$delta" -ge 5 ] && [ "$delta" -le 60 ]; } || die "5 requests -> $delta flows (loop?)"
pass "5 requests -> $delta flows"

stepn "bypass path: forced tlsrec rule for example.com"
printf '\n[domains]\nexample.com = tlsrec\n' | sudo tee -a "$CONF" >/dev/null
sudo dpictl restart >/dev/null || die "restart failed"
wait_running || die "not running after restart"
c="$(fetch https://example.com/)"; ok "$c" || die "example.com with tlsrec -> '$c'"
wait_status
[ "$(field bypassed)" -ge 1 ] || die "bypassed=$(field bypassed); the TLSREC path was not used"
pass "example.com via tlsrec: HTTP $c; bypassed=$(field bypassed)"

stepn "throughput and resource use"
pid="$(daemon_pid)"
curl -sS -o /dev/null --max-time 90 -w 'through dpi-proxy: %{size_download} bytes in %{time_total}s (%{speed_download} B/s)\n' \
	'https://speed.cloudflare.com/__down?bytes=50000000' || true
for u in https://www.wikipedia.org/ https://github.com/ https://www.apple.com/ https://example.com/; do
	for _ in 1 2 3; do fetch "$u" >/dev/null & done
done
wait
ps -o pid=,rss=,vsz=,%cpu=,time= -p "$pid" | awk '{ printf "daemon pid %s: RSS %.1f MB, VSZ %.0f MB, CPU now %s%%, CPU time %s\n", $1, $2/1024, $3/1024, $4, $5 }'
ps -o pid=,rss= -p "$(pgrep -f -- '--pf-watchdog' | head -n 1)" | awk '{ printf "watchdog pid %s: RSS %.1f MB\n", $1, $2/1024 }'
pass "measured"

stepn "dpictl (as a normal user, by name)"
out="$(dpictl status --verbose 2>&1)"; echo "$out"
echo "$out" | grep -q '^engine:    running' || die "status --verbose: engine not running"
for k in mode dns network flows direct bypassed failures pf watchdog; do
	echo "$out" | grep -q "^$k:" || die "status --verbose lacks '$k'"
done
short="$(dpictl status 2>&1)"; echo "$short"
echo "$short" | grep -q '^Service: Running' || die "short status: service not Running"
echo "$short" | grep -q '^Protection: Active' || die "short status: protection not Active"
out="$(dpictl diagnose example.com 2>&1)"; echo "$out"
echo "$out" | grep -q '^https:        HTTP [23]' || die "diagnose failed"
out="$(dpictl logs 5 2>&1)"; echo "$out"
dpictl logs 200 | grep -q 'transparent mode: TCP/443' || die "logs lack the startup line"
dpictl strategy example.com | grep -q 'tlsrec (manual' || die "strategy"
out="$(sudo dpictl status --verbose 2>&1)"
echo "$out" | grep -q '^pf rules:' || die "status as root lacks the live PF rule count"
dpictl stop >/dev/null 2>&1 && die "stop without sudo should refuse"
dpictl version | grep -q . || die "version printed nothing"
pass "dpictl status/diagnose/logs/strategy/version report correctly"

stepn "dpictl doctor"
dpictl doctor || die "doctor reported a failure while the service is healthy"
pass "doctor: no failures"

stepn "dpictl support-bundle (redaction)"
bundle="/tmp/dpi-e2e-support-$$.tar.gz"
dpictl support-bundle "$bundle" || die "support-bundle failed"
[ -s "$bundle" ] || die "support-bundle produced an empty/missing archive"
bdir="/tmp/dpi-e2e-support-$$"
mkdir -p "$bdir"
tar -xzf "$bundle" -C "$bdir"
[ -f "$bdir/version.txt" ] || die "support-bundle missing version.txt"
grep -rl "$HOME" "$bdir" >/dev/null 2>&1 && die "support-bundle leaked \$HOME into the archive"
[ -f "$bdir/dns-history-summary.txt" ] && ! grep -q "raw per-domain/per-IP records are not included" "$bdir/dns-history-summary.txt" \
	&& die "support-bundle included raw DNS decision history instead of a summary"
rm -rf "$bdir" "$bundle"
pass "support-bundle archive redacted correctly"

stepn "dpi-proxy-ctl (compatibility alias)"
out="$(dpi-proxy-ctl status 2>&1)"; echo "$out"
echo "$out" | grep -q '^Service: Running' || die "alias status: service not Running"
out="$(dpi-proxy-ctl diagnose example.com 2>&1)"; echo "$out"
echo "$out" | grep -q '^https:        HTTP [23]' || die "alias diagnose failed"
pass "dpi-proxy-ctl still works as an alias"

stepn "restart keeps working"
sudo dpictl restart >/dev/null || die "restart failed"
wait_running || die "not running after restart"
c="$(fetch https://www.wikipedia.org/)"; ok "$c" || die "after restart -> '$c'"
pass "after restart: HTTP $c (pid $(daemon_pid))"

stepn "stop = ordinary networking, PF as before"
sudo dpictl stop || die "stop failed"
[ -z "$(daemon_pid)" ] || die "still running"
anchor_empty || die "rules or tables left in $ANCHOR after stop"
sleep 1
pgrep -f -- '--pf-watchdog' >/dev/null && die "watchdog still running after a clean stop"
pf_state >/tmp/dpi-e2e-pf-stopped.txt
diff /tmp/dpi-e2e-pf-before.txt /tmp/dpi-e2e-pf-stopped.txt || die "PF state differs from before install"
c="$(fetch https://example.com/)"; ok "$c" || die "stopped -> '$c'"
dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null; sleep 1
dscacheutil -q host -a name example.com | grep -q '^ip_address:' || die "DNS broken after stop"
pass "stopped: anchor empty, PF exactly as before, HTTPS $c, DNS OK"

stepn "crash (SIGKILL of the daemon) = fail-open at once, then launchd restarts it"
sudo dpictl start >/dev/null || die "start failed"
wait_running || die "not running after start"
old="$(daemon_pid)"
sudo kill -9 "$old"
sleep 0.5
[ "$(anchor_rules)" -eq 0 ] || note "rules still present 0.5 s after the crash"
c="$(fetch https://example.com/)"; ok "$c" || die "right after a crash -> '$c' (not fail-open)"
sudo grep -q 'dpi-proxy exited unexpectedly: PF rules removed' "$LOG" || die "watchdog did not log the cleanup"
i=0
while [ $i -lt 40 ]; do
	p="$(daemon_pid)"; [ -n "$p" ] && [ "$p" != "$old" ] && break
	sleep 0.5; i=$((i + 1))
done
wait_running || die "launchd did not restart the daemon after the crash"
[ "$(anchor_rules)" -ge 4 ] || die "rules not reinstalled after the restart"
c="$(fetch https://example.com/)"; ok "$c" || die "after automatic restart -> '$c'"
pass "killed pid $old: HTTPS still worked at once; restarted as pid $(daemon_pid); HTTPS $c"

stepn "hang (SIGSTOP) = watchdog removes the rules within 30 s"
p="$(daemon_pid)"
sudo kill -STOP "$p"
t=0
while [ $t -lt 45 ] && [ "$(anchor_rules)" -gt 0 ]; do sleep 1; t=$((t + 1)); done
[ "$(anchor_rules)" -eq 0 ] || { sudo kill -CONT "$p"; die "rules still present ${t}s after the daemon hung"; }
c="$(fetch https://example.com/)"; ok "$c" || { sudo kill -CONT "$p"; die "while hung -> '$c'"; }
sudo kill -CONT "$p"
t2=0
while [ $t2 -lt 30 ] && [ "$(anchor_rules)" -lt 4 ]; do sleep 1; t2=$((t2 + 1)); done
[ "$(anchor_rules)" -ge 4 ] || die "rules not reinstalled after the daemon resumed"
c="$(fetch https://example.com/)"; ok "$c" || die "after resume -> '$c'"
pass "hung: rules removed after ${t}s, HTTPS $c meanwhile; resumed: reinstalled after ${t2}s"

stepn "crash of daemon and watchdog together: launchd's restart cleans up"
sudo pkill -9 -f '^/usr/local/bin/dpi-proxy'
t=0
note "rules right after killing both: $(anchor_rules) (stay until launchd restarts the daemon)"
while [ $t -lt 30 ] && ! ok "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 https://example.com/ 2>/dev/null)"; do
	sleep 1; t=$((t + 1))
done
note "HTTPS worked again after ${t}s"
[ $t -lt 30 ] || die "no HTTPS for 30 s after killing daemon and watchdog"
wait_running || die "launchd did not restart the daemon"
c="$(fetch https://example.com/)"; ok "$c" || die "after restart -> '$c'"
[ "$(pgrep -f -- '--pf-watchdog' | wc -l | tr -d ' ')" -eq 1 ] || die "not exactly one watchdog"
pass "restarted as pid $(daemon_pid) with one watchdog; HTTPS $c"

stepn "uninstall leaves nothing behind"
( cd "$PKG" && sudo ./uninstall.sh ) || die "uninstall.sh failed"
[ -e "/Library/LaunchDaemons/$LABEL.plist" ] && die "plist left"
launchctl print "system/$LABEL" >/dev/null 2>&1 && die "launchd job left"
for f in /usr/local/bin/dpi-proxy /usr/local/bin/dpictl /usr/local/bin/dpi-proxy-ctl /usr/local/etc/dpi-proxy \
	/usr/local/var/dpi-proxy /var/run/dpi-proxy /var/log/dpi-proxy.log /var/log/dpi-proxy.stderr.log; do
	[ -e "$f" ] && die "$f left"
done
# a new shell: this one still has the old location hashed
/bin/sh -c 'command -v dpictl' >/dev/null && die "dpictl still on the PATH"
/bin/sh -c 'command -v dpi-proxy-ctl' >/dev/null && die "dpi-proxy-ctl still on the PATH"
pgrep -f '^/usr/local/bin/dpi-proxy' >/dev/null && die "a dpi-proxy process is left"
anchor_empty || die "rules or tables left in $ANCHOR"
sudo pfctl -s References 2>/dev/null | grep -q '[0-9]\{8,\}' && [ "$(sed -n 1p /tmp/dpi-e2e-pf-before.txt)" = Disabled ] \
	&& die "a PF enable reference is still held"
pf_state >/tmp/dpi-e2e-pf-after.txt
diff /tmp/dpi-e2e-pf-before.txt /tmp/dpi-e2e-pf-after.txt || die "PF state differs from before install"
sudo pfctl -s References 2>/dev/null
c="$(fetch https://example.com/)"; ok "$c" || die "after uninstall -> '$c'"
pass "no plist, job, binaries, config, state, logs, processes, PF rules, tables or PF reference; PF as before; HTTPS $c"

stepn "clean reinstall"
( cd "$PKG" && sudo ./install.sh ) || die "reinstall failed"
wait_running || die "not running after reinstall"
c="$(fetch https://github.com/)"; ok "$c" || die "after reinstall -> '$c'"
( cd "$PKG" && sudo ./uninstall.sh ) || die "second uninstall failed"
pf_state >/tmp/dpi-e2e-pf-after2.txt
diff /tmp/dpi-e2e-pf-before.txt /tmp/dpi-e2e-pf-after2.txt || die "PF state differs after the second uninstall"
pass "reinstalled (HTTPS $c) and uninstalled cleanly again"

printf '\nALL MACOS E2E CHECKS PASSED (%s, macOS %s, %ss)\n' "$(uname -m)" "$(sw_vers -productVersion)" "$(( $(date +%s) - t0 ))"
