#Requires -Version 5.1
<#
.SYNOPSIS
  dpi-proxy-ctl for Windows: the same commands as on Linux.
    dpi-proxy-ctl status | start | stop | restart | logs [N] | diagnose HOST
  start/stop/restart need an elevated terminal.
#>
param(
    [Parameter(Position = 0)][string]$Command = 'status',
    [Parameter(Position = 1)][string]$Arg
)

$Service    = 'dpi-proxy'
$DataDir    = Join-Path $env:ProgramData 'dpi-proxy'
$StatusFile = Join-Path $DataDir 'transparent.status'
$LogFile    = Join-Path $DataDir 'dpi-proxy.log'

function Field($name) {
    if (-not (Test-Path $StatusFile)) { return '' }
    $m = Select-String -Path $StatusFile -Pattern "^${name}: (.*)$" | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value } else { return '' }
}

function Show-Status {
    $svc = Get-Service $Service -ErrorAction SilentlyContinue
    $state = if ($svc) { $svc.Status.ToString().ToLower() } else { 'not installed' }
    Write-Host "service:   $Service ($state)"
    if (-not $svc -or $svc.Status -ne 'Running' -or -not (Test-Path $StatusFile)) {
        Write-Host 'engine:    not running — HTTPS and DNS go out directly, untouched'
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
    if ($c -and $c -ne 'none') { Write-Host "CONFLICT:  $c — stop the other tool" -ForegroundColor Yellow }
}

function Show-Diagnose($domain) {
    if (-not $domain) { Write-Host 'usage: dpi-proxy-ctl diagnose HOST'; exit 1 }
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

switch ($Command) {
    'status'   { Show-Status }
    'start'    { Start-Service $Service; Show-Status }
    'stop'     { Stop-Service $Service; Write-Host 'stopped; networking is back to normal (unbypassed)' }
    'restart'  { Restart-Service $Service; Start-Sleep -Seconds 2; Show-Status }
    'logs'     {
        $n = if ($Arg) { [int]$Arg } else { 100 }
        if (Test-Path $LogFile) { Get-Content $LogFile -Tail $n } else { Write-Host "no log yet ($LogFile)" }
    }
    'diagnose' { Show-Diagnose $Arg }
    default    {
        Write-Host 'Usage: dpi-proxy-ctl status | start | stop | restart | logs [N] | diagnose HOST'
        exit 1
    }
}
