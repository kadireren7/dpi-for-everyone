#Requires -Version 5.1
<#
.SYNOPSIS
  dpictl for Windows: the same commands as on Linux and macOS.
    dpictl status [--verbose] | start | stop | restart | logs [N]
    dpictl diagnose HOST | doctor | support-bundle [FILE] | version
  start/stop/restart need an elevated terminal.

  dpi-proxy-ctl.cmd is kept as a compatibility alias for dpictl.cmd.
#>
param(
    [Parameter(Position = 0)][string]$Command = 'status',
    [Parameter(Position = 1)][string]$Arg
)

$Service    = 'dpi-proxy'
$InstDir    = Join-Path $env:ProgramFiles 'dpi-proxy'
$DataDir    = Join-Path $env:ProgramData 'dpi-proxy'
$StatusFile = Join-Path $DataDir 'transparent.status'
$LogFile    = Join-Path $DataDir 'dpi-proxy.log'
$Exe        = Join-Path $InstDir 'dpi-proxy.exe'

function Field($name) {
    if (-not (Test-Path $StatusFile)) { return '' }
    $m = Select-String -Path $StatusFile -Pattern "^${name}: (.*)$" | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value } else { return '' }
}

function Is-Elevated {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VersionString {
    if (Test-Path $Exe) {
        $out = & $Exe --version 2>$null
        if ($out -match 'dpi-proxy (.+)') { return $Matches[1] }
    }
    return $null
}

function Show-StatusShort {
    $ver = Get-VersionString
    if ($ver) { Write-Host "dpi-for-everyone $ver" } else { Write-Host 'dpi-for-everyone (version unknown - dpi-proxy.exe not found)' }
    $svc = Get-Service $Service -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host 'Service: Not installed'
        Write-Host 'Protection: Inactive'
        Write-Host 'DNS: N/A'
        Write-Host 'Mode: N/A'
        Write-Host 'Bypassed: 0'
        Write-Host 'Failures: 0'
        return
    }
    if ($svc.Status -eq 'Running') { Write-Host 'Service: Running' } else { Write-Host "Service: $($svc.Status)" }
    if ($svc.Status -ne 'Running' -or -not (Test-Path $StatusFile)) {
        Write-Host 'Protection: Inactive'
        Write-Host 'DNS: N/A'
        Write-Host 'Mode: N/A'
        Write-Host 'Bypassed: 0'
        Write-Host 'Failures: 0'
        return
    }
    $engine = Field engine
    if ($engine -eq 'running') { Write-Host 'Protection: Active' } else { Write-Host 'Protection: Starting' }
    $fails = Field dns_failures
    switch (Field dns_intercept) {
        'doh' {
            if (-not $fails -or $fails -eq '0') { Write-Host 'DNS: Healthy' }
            else { Write-Host "DNS: Degraded ($fails failure(s))" }
        }
        'off' { Write-Host 'DNS: Not intercepted' }
        default { Write-Host 'DNS: Unknown' }
    }
    $mode = Field mode
    if ($mode) { Write-Host ("Mode: " + $mode.Substring(0,1).ToUpper() + $mode.Substring(1)) } else { Write-Host 'Mode: Unknown' }
    Write-Host "Bypassed: $(Field bypassed)"
    Write-Host "Failures: $(Field failures)"
}

function Show-StatusVerbose {
    $svc = Get-Service $Service -ErrorAction SilentlyContinue
    $state = if ($svc) { $svc.Status.ToString().ToLower() } else { 'not installed' }
    Write-Host "service:   $Service ($state)"
    if (-not $svc -or $svc.Status -ne 'Running' -or -not (Test-Path $StatusFile)) {
        Write-Host 'engine:    not running - HTTPS and DNS go out directly, untouched'
        return
    }
    Write-Host "engine:    $(Field engine) ($(Field interception))"
    Write-Host "mode:      $(Field mode)"
    Write-Host "dns:       $(Field dns) resolvers; interception: $(Field dns_intercept) ($(Field dns_queries) queries, $(Field dns_failures) failed)"
    Write-Host "network:   $(Field network)"
    Write-Host "flows:     $(Field flows) total, $(Field active) active"
    Write-Host "direct:    $(Field direct)"
    Write-Host "bypassed:  $(Field bypassed)"
    Write-Host "passthru:  $(Field passthrough) (no hostname / manual pass / cooldown)"
    Write-Host "failures:  $(Field failures)"
    Write-Host "verified:  $(Field verified_ok) ok, $(Field verified_bad) rejected"
    Write-Host "learned:   $(Field decisions) decision(s); last: $(Field last_learned)"
    $c = Field conflict
    if ($c -and $c -ne 'none') { Write-Host "CONFLICT:  $c - stop the other tool" -ForegroundColor Yellow }
}

function Show-Diagnose($domain) {
    if (-not $domain) { Write-Host 'usage: dpictl diagnose HOST'; exit 1 }
    Write-Host "== $domain"
    $ips = (Resolve-DnsName $domain -Type A -DnsOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) -join ' '
    Write-Host "system DNS:   $ips"
    try {
        $r = Invoke-WebRequest -Uri "https://$domain/" -Method Head -UseBasicParsing -TimeoutSec 15
        Write-Host "https:        HTTP $($r.StatusCode) (certificate verified by Windows)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code) { Write-Host "https:        HTTP $code (certificate verified by Windows)" }
        else { Write-Host "https:        FAILED: $($_.Exception.Message)" }
    }
    if (Test-Path $LogFile) {
        Write-Host 'recent log lines mentioning it:'
        Select-String -Path $LogFile -SimpleMatch " $domain" | Select-Object -Last 5 |
            ForEach-Object { Write-Host "  $($_.Line)" }
    }
}

# ---- doctor -------------------------------------------------------------

$script:DoctorFailed = $false
function Check($level, $msg) {
    if ($level -eq 'FAIL') { $script:DoctorFailed = $true }
    $color = switch ($level) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'White' } }
    Write-Host ("[{0,-4}] {1}" -f $level, $msg) -ForegroundColor $color
}

function Doctor-Permissions {
    if (Is-Elevated) { Check PASS 'permissions: running elevated - full diagnostics available' }
    else { Check WARN 'permissions: not elevated - some checks are limited; re-run as Administrator for full detail' }
    if (Test-Path $Exe) { Check PASS "permissions: $Exe is present" }
    else { Check FAIL "permissions: dpi-proxy.exe not found at $Exe" }
}

function Doctor-Service {
    $svc = Get-Service $Service -ErrorAction SilentlyContinue
    if (-not $svc) { Check WARN "service: $Service is not installed"; return }
    if ($svc.Status -eq 'Running') { Check PASS "service: $Service is running" }
    elseif ($svc.Status -eq 'Stopped') { Check WARN "service: $Service is stopped" }
    else { Check WARN "service: $Service is $($svc.Status)" }
}

function Doctor-Interception {
    $svc = Get-Service $Service -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        Check WARN 'interception: service not running - HTTPS/DNS are not intercepted'
        return
    }
    $wd = Get-Service WinDivert -ErrorAction SilentlyContinue
    if ($wd -and $wd.Status -eq 'Running') { Check PASS 'interception: WinDivert driver loaded' }
    elseif ($wd) { Check FAIL "interception: WinDivert service present but $($wd.Status)" }
    else { Check WARN 'interception: WinDivert driver service not found (may not have loaded yet)' }
}

function Doctor-Dns {
    if (-not (Test-Path $StatusFile)) { Check WARN 'dns: no status file yet'; return }
    $fails = Field dns_failures
    switch (Field dns_intercept) {
        'doh' {
            if (-not $fails -or $fails -eq '0') { Check PASS 'dns: DNS-over-HTTPS active, 0 failures' }
            else { Check WARN "dns: DNS-over-HTTPS active but $fails failure(s)" }
        }
        'off' { Check WARN 'dns: interception is off' }
        default { Check WARN "dns: unexpected state `"$(Field dns_intercept)`"" }
    }
}

function Doctor-Reachability {
    try {
        $r = Invoke-WebRequest -Uri 'https://example.com/' -Method Head -UseBasicParsing -TimeoutSec 8
        Check PASS "reachability: https://example.com/ -> HTTP $($r.StatusCode)"
    } catch {
        Check FAIL "reachability: https://example.com/ failed: $($_.Exception.Message)"
    }
}

function Doctor-Bypass {
    if (-not (Test-Path $Exe)) { Check WARN 'bypass path: dpi-proxy.exe not found'; return }
    $caps = & $Exe --capabilities 2>$null
    if ($caps -match '^transparent_mode: supported') { Check PASS 'bypass path: this binary supports transparent mode' }
    else { Check FAIL 'bypass path: this binary was built without transparent mode support' }
}

function Doctor-Conflicts {
    $other = Get-Process -Name goodbyedpi, winws -ErrorAction SilentlyContinue
    $c = Field conflict
    $found = @()
    if ($other) { $found += ($other | Select-Object -Expand Name -Unique) }
    if ($c -and $c -ne 'none') { $found += $c }
    if ($found.Count -gt 0) {
        Check WARN ("conflicts: other DPI/interception tool(s) detected: " + ($found -join ', ') + " - dpi-proxy does not disable them; stop one manually")
    } else {
        Check PASS 'conflicts: no other known DPI-bypass tool detected'
    }
}

function Doctor-Vpn {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'TAP|TUN|WireGuard|VPN|OpenVPN' }
    if ($adapters) {
        $names = ($adapters | Select-Object -Expand Name) -join ', '
        Check WARN "vpn: active VPN/tunnel adapter(s) ($names) - if one filters HTTPS, it may interact with dpi-proxy"
    } else {
        Check PASS 'vpn: no active VPN/tunnel adapter detected'
    }
}

function Doctor-Stale {
    $svc = Get-Service $Service -ErrorAction SilentlyContinue
    $wd = Get-Service WinDivert -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { Check PASS 'stale rules: service is running, nothing to check'; return }
    if ($wd -and $wd.Status -eq 'Running' -and (-not (Get-Process -Name goodbyedpi, winws -ErrorAction SilentlyContinue))) {
        Check WARN 'stale rules: WinDivert driver still loaded although dpi-proxy is stopped and no other known WinDivert tool is running'
    } else {
        Check PASS 'stale rules: none found'
    }
}

function Invoke-Doctor {
    Write-Host "dpictl doctor - $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Write-Host ''
    Doctor-Permissions
    Doctor-Service
    Doctor-Interception
    Doctor-Dns
    Doctor-Reachability
    Doctor-Bypass
    Doctor-Conflicts
    Doctor-Vpn
    Doctor-Stale
    Write-Host ''
    if ($script:DoctorFailed) {
        Write-Host 'Result: one or more checks FAILED - see above.'
        exit 1
    }
    Write-Host 'Result: no failures.'
    exit 0
}

# ---- support-bundle -------------------------------------------------------

function Protect-Text([string]$text) {
    if (-not $text) { return $text }
    $out = $text -replace '(?i)(token|key|secret|password)[=: ]+[A-Za-z0-9_.\-]{4,}', '$1=[REDACTED]'
    $userHome = $env:USERPROFILE
    if ($userHome) { $out = $out -replace [regex]::Escape($userHome), '~' }
    $userName = $env:USERNAME
    if ($userName) { $out = $out -replace "\b$([regex]::Escape($userName))\b", '[user]' }
    return $out
}

function Invoke-SupportBundle([string]$OutFile) {
    $ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $tmp = Join-Path $env:TEMP "dpictl-support-$ts"
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    if (-not $OutFile) { $OutFile = Join-Path (Get-Location) "dpictl-support-$ts.zip" }

    $ver = Get-VersionString
    @(
        'dpictl support-bundle'
        "generated: $ts (UTC)"
        "version:   $ver"
        "binary:    $Exe"
    ) | Set-Content (Join-Path $tmp 'version.txt')

    @(
        "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
        "Version: $([System.Environment]::OSVersion.VersionString)"
        "Arch: $env:PROCESSOR_ARCHITECTURE"
    ) | Set-Content (Join-Path $tmp 'os.txt')

    # Show-Status{Short,Verbose} print with Write-Host, which does not
    # flow through the success stream that Out-String reads by
    # default; *>&1 merges every stream (including Write-Host's
    # Information stream) into it first.
    ((Show-StatusShort *>&1 | Out-String) + "`n" + (Show-StatusVerbose *>&1 | Out-String)) |
        Set-Content (Join-Path $tmp 'status.txt')

    $prevFailed = $script:DoctorFailed
    $script:DoctorFailed = $false
    try {
        $doctorOut = & {
            Doctor-Permissions
            Doctor-Service
            Doctor-Interception
            Doctor-Dns
            Doctor-Reachability
            Doctor-Bypass
            Doctor-Conflicts
            Doctor-Vpn
            Doctor-Stale
        } *>&1 | Out-String
    } finally {
        $script:DoctorFailed = $prevFailed
    }
    $doctorOut | Set-Content (Join-Path $tmp 'doctor.txt')

    $svc = Get-Service $Service -ErrorAction SilentlyContinue
    if ($svc) { (Protect-Text ($svc | Format-List | Out-String)) | Set-Content (Join-Path $tmp 'service-state.txt') }

    if (Test-Path $LogFile) {
        (Get-Content $LogFile -Tail 500 | ForEach-Object { Protect-Text $_ }) |
            Set-Content (Join-Path $tmp 'log.txt')
    }

    $conf = Join-Path $DataDir 'strategy.conf'
    if (Test-Path $conf) {
        (Get-Content $conf | ForEach-Object { Protect-Text $_ }) | Set-Content (Join-Path $tmp 'strategy.conf')
    }

    $decisions = Join-Path $DataDir 'tp-decisions.conf'
    if (Test-Path $decisions) {
        $n = (Get-Content $decisions | Measure-Object -Line).Lines
        @(
            "learned decisions on record: $n"
            '(raw per-domain/per-IP records are not included in support bundles)'
        ) | Set-Content (Join-Path $tmp 'dns-history-summary.txt')
    }

    if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
    Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $OutFile
    Remove-Item $tmp -Recurse -Force

    Write-Host "Wrote $OutFile"
    Write-Host 'Redacted: tokens/keys/passwords, %USERPROFILE%, username, and per-domain DNS history (counts only).'
    Write-Host 'Review it before sharing - it may still contain domain names you visited and log timestamps.'
}

switch ($Command) {
    'status' {
        if ($Arg -eq '--verbose' -or $Arg -eq '-v') { Show-StatusVerbose } else { Show-StatusShort }
    }
    'start'    { Start-Service $Service; Show-StatusVerbose }
    'stop'     { Stop-Service $Service; Write-Host 'stopped; networking is back to normal (unbypassed)' }
    'restart'  { Restart-Service $Service; Start-Sleep -Seconds 2; Show-StatusVerbose }
    'logs'     {
        $n = if ($Arg) { [int]$Arg } else { 100 }
        if (Test-Path $LogFile) { Get-Content $LogFile -Tail $n } else { Write-Host "no log yet ($LogFile)" }
    }
    'diagnose'       { Show-Diagnose $Arg }
    'doctor'         { Invoke-Doctor }
    'support-bundle' { Invoke-SupportBundle $Arg }
    'version'        {
        $ver = Get-VersionString
        if ($ver) { Write-Host "dpi-for-everyone $ver" } else { Write-Host 'dpi-for-everyone (version unknown - dpi-proxy.exe not found)' }
    }
    default    {
        Write-Host 'Usage: dpictl status [--verbose] | start | stop | restart | logs [N] | diagnose HOST | doctor | support-bundle [FILE] | version'
        exit 1
    }
}
