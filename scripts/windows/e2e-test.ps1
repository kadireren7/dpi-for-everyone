#Requires -Version 5.1
<#
  End-to-end test of Windows transparent mode on a real machine
  (CI: GitHub's windows-latest runner, Administrator). Installs from
  a packaged folder, then checks the whole lifecycle. Exits non-zero
  on the first failure. Never run it on a machine whose dpi-proxy
  installation you want to keep: it uninstalls at the end.

    powershell -ExecutionPolicy Bypass -File e2e-test.ps1 -Package <dir>
#>
param([Parameter(Mandatory = $true)][string]$Package)

$ErrorActionPreference = 'Stop'
$DataDir    = Join-Path $env:ProgramData 'dpi-proxy'
$StatusFile = Join-Path $DataDir 'transparent.status'
$LogFile    = Join-Path $DataDir 'dpi-proxy.log'
$InstDir    = Join-Path $env:ProgramFiles 'dpi-proxy'
$script:step = 0

function Step($m) { $script:step++; Write-Host "`n=== [$script:step] $m" }
function Pass($m) { Write-Host "PASS: $m" -ForegroundColor Green }
function Die($m) {
    Write-Host "FAIL: $m" -ForegroundColor Red
    if (Test-Path $LogFile) { Write-Host '--- service log ---'; Get-Content $LogFile -Tail 60 }
    if (Test-Path $StatusFile) { Write-Host '--- status ---'; Get-Content $StatusFile }
    exit 1
}
function Field($name) {
    $m = Select-String -Path $StatusFile -Pattern "^${name}: (.*)$" | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value } else { return '' }
}
# the status file is rewritten every 10 s (heartbeat)
function Wait-Status { Start-Sleep -Seconds 11 }
function Fetch($url) {
    $out = & curl.exe -sS -o NUL -w '%{http_code}' --max-time 20 $url 2>&1
    return "$out"
}

Step 'install'
& powershell -ExecutionPolicy Bypass -File (Join-Path $Package 'install.ps1')
if ($LASTEXITCODE -ne 0) { Die "install.ps1 exited $LASTEXITCODE" }
if ((Get-Service dpi-proxy).Status -ne 'Running') { Die 'service not running' }
Pass 'installed; service running; installer health check (DNS + HTTPS through it) passed'

Step 'normal HTTPS works and is intercepted'
foreach ($u in 'https://example.com/', 'https://www.wikipedia.org/', 'https://github.com/') {
    $c = Fetch $u
    if ($c -notmatch '^[23]\d\d$') { Die "$u -> '$c'" }
}
Wait-Status
if ([int](Field flows) -lt 3) { Die "expected >= 3 intercepted flows, status says $(Field flows)" }
if ([int](Field failures) -ne 0) { Die "failures: $(Field failures)" }
Pass "3 sites OK; flows=$(Field flows) direct=$(Field direct) failures=0"

Step 'DNS goes through the forwarder (DoH)'
Clear-DnsClientCache
Resolve-DnsName "dpi-e2e-$(Get-Random).example.org" -ErrorAction SilentlyContinue | Out-Null
Resolve-DnsName example.net -Type A -ErrorAction Stop | Out-Null
Wait-Status
if ((Field dns_intercept) -ne 'doh') { Die "dns_intercept: $(Field dns_intercept)" }
if ([int](Field dns_queries) -lt 1) { Die 'no DNS query reached the forwarder' }
Pass "dns_intercept=doh dns_queries=$(Field dns_queries) dns_failures=$(Field dns_failures)"

Step 'no redirect loop: the service''s own connections are not intercepted'
$before = [int](Field flows)
1..5 | ForEach-Object { Fetch 'https://example.com/' | Out-Null }
Wait-Status
$delta = [int](Field flows) - $before
# background traffic on the machine may add a few; a loop adds hundreds
if ($delta -lt 5 -or $delta -gt 60) { Die "5 requests made $delta intercepted flows (loop?)" }
Pass "5 requests -> $delta flows"

Step 'bypass path: forced tlsrec rule for example.com'
Add-Content -Encoding ASCII (Join-Path $DataDir 'strategy.conf') "`n[domains]`nexample.com = tlsrec"
Restart-Service dpi-proxy
Start-Sleep -Seconds 3
$c = Fetch 'https://example.com/'
if ($c -notmatch '^[23]\d\d$') { Die "example.com with tlsrec -> '$c'" }
Wait-Status
if ([int](Field bypassed) -lt 1) { Die "bypassed=$(Field bypassed); the TLSREC path was not used" }
Pass "example.com via tlsrec: HTTP $c; bypassed=$(Field bypassed)"

Step 'restart keeps working'
Restart-Service dpi-proxy
Start-Sleep -Seconds 3
$c = Fetch 'https://www.wikipedia.org/'
if ($c -notmatch '^[23]\d\d$') { Die "after restart -> '$c'" }
Pass "after restart: HTTP $c"

Step 'stop = ordinary networking'
Stop-Service dpi-proxy
$c = Fetch 'https://example.com/'
if ($c -notmatch '^[23]\d\d$') { Die "with service stopped -> '$c'" }
Resolve-DnsName example.com -Type A -ErrorAction Stop | Out-Null
Pass "stopped: HTTPS $c, DNS OK"

Step 'crash = fail-open, then automatic restart'
Start-Service dpi-proxy
Start-Sleep -Seconds 3
Stop-Process -Name dpi-proxy -Force
Start-Sleep -Milliseconds 500
$c = Fetch 'https://example.com/'
if ($c -notmatch '^[23]\d\d$') { Die "right after a crash -> '$c' (not fail-open)" }
$back = $false
foreach ($i in 1..30) { Start-Sleep -Seconds 1; if ((Get-Service dpi-proxy).Status -eq 'Running') { $back = $true; break } }
if (-not $back) { Die 'service was not restarted after the crash' }
Start-Sleep -Seconds 3
$c2 = Fetch 'https://example.com/'
if ($c2 -notmatch '^[23]\d\d$') { Die "after automatic restart -> '$c2'" }
Pass "killed: HTTPS still $c; restarted automatically; HTTPS $c2"

Step 'dpi-proxy-ctl'
$ctl = Join-Path $InstDir 'dpi-proxy-ctl.cmd'
$out = (& $ctl status 2>&1 | Out-String)
Write-Host $out
if ($LASTEXITCODE -ne 0 -or $out -notmatch 'engine:\s+running' -or $out -notmatch 'bypassed:') {
    Die 'dpi-proxy-ctl status did not report a running engine'
}
$out = (& $ctl diagnose example.com 2>&1 | Out-String)
Write-Host $out
if ($LASTEXITCODE -ne 0 -or $out -notmatch 'https:\s+HTTP \d+') { Die 'dpi-proxy-ctl diagnose failed' }
$out = (& $ctl logs 5 2>&1 | Out-String)
Write-Host $out
if ($LASTEXITCODE -ne 0 -or $out -notmatch 'transparent mode:') { Die 'dpi-proxy-ctl logs failed' }
Pass 'ctl status/diagnose/logs report correctly'

Step 'uninstall cleans only our own state'
& powershell -ExecutionPolicy Bypass -File (Join-Path $InstDir 'uninstall.ps1') -Purge
Start-Sleep -Seconds 3
if (Get-Service dpi-proxy -ErrorAction SilentlyContinue) { Die 'service still present' }
if (Get-NetFirewallRule -Name dpi-proxy -ErrorAction SilentlyContinue) { Die 'firewall rule still present' }
if (Test-Path $DataDir) { Die "$DataDir still present after -Purge" }
if (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -contains $InstDir) { Die 'PATH entry still present' }
$c = Fetch 'https://example.com/'
if ($c -notmatch '^[23]\d\d$') { Die "after uninstall -> '$c'" }
Pass "uninstalled; HTTPS $c"

Write-Host "`nALL WINDOWS E2E CHECKS PASSED" -ForegroundColor Green
