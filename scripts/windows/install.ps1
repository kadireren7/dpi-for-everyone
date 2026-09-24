#Requires -Version 5.1
<#
.SYNOPSIS
  Installs dpi-proxy transparent mode on Windows as the "dpi-proxy"
  service: after this, HTTPS and DNS from every application go through
  the automatic DPI bypass, with no proxy or DNS settings anywhere.

.DESCRIPTION
  Run from the unpacked release folder, in an elevated PowerShell:
      powershell -ExecutionPolicy Bypass -File .\install.ps1

  Installs (and scripts\windows\uninstall.ps1 removes exactly that):
    %ProgramFiles%\dpi-proxy\   dpi-proxy.exe, WinDivert.dll,
                                WinDivert64.sys, WinDivert-LICENSE.txt,
                                dpi-proxy-ctl.ps1/.cmd, uninstall.ps1
    %ProgramData%\dpi-proxy\    strategy.conf (kept on reinstall),
                                learned decisions, status, log
    service "dpi-proxy"         automatic start, restart on failure
    firewall rule "dpi-proxy"   inbound allow for dpi-proxy.exe only
    machine PATH                + %ProgramFiles%\dpi-proxy

  WinDivert (https://reqrypt.org/windivert.html) is a third-party,
  signed packet-capture driver (LGPLv3/GPLv2) that dpi-proxy uses to
  redirect this machine's own outgoing HTTPS/DNS to itself. Windows
  loads it when the service starts. Some antivirus products flag it
  as "riskware" because DPI-bypass tools use it; it is the unmodified
  official build (see WinDivert-LICENSE.txt).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Service   = 'dpi-proxy'
$InstDir   = Join-Path $env:ProgramFiles 'dpi-proxy'
$DataDir   = Join-Path $env:ProgramData 'dpi-proxy'
$StatusFile = Join-Path $DataDir 'transparent.status'
$Src       = $PSScriptRoot

function Log($m) { Write-Host "[install] $m" }
function Fail($m) { Write-Host "[install] ERROR: $m" -ForegroundColor Red }

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'this installer sets up a system service and needs an elevated (Administrator) PowerShell.'
    exit 1
}

# Files come from the release folder (next to this script) or, in a
# source checkout, from the repository root.
$need = 'dpi-proxy.exe', 'WinDivert.dll', 'WinDivert64.sys'
$from = $Src
if (-not (Test-Path (Join-Path $from 'dpi-proxy.exe'))) {
    $from = Resolve-Path (Join-Path $Src '..\..')
}
foreach ($f in $need) {
    if (-not (Test-Path (Join-Path $from $f))) {
        Fail "missing $f (looked in $Src and $from)"
        exit 2
    }
}

Log '[1/6] Third-party component notice'
Write-Host '  dpi-proxy uses the WinDivert driver (signed, LGPLv3/GPLv2,'
Write-Host '  https://reqrypt.org/windivert.html) to redirect this machine''s own'
Write-Host '  outgoing HTTPS and DNS to the local dpi-proxy service. It does not'
Write-Host '  decrypt anything and does not send traffic to any remote server.'

$installed = $false
try {
    Log '[2/6] Stopping a previous installation (if any)...'
    if (Get-Service $Service -ErrorAction SilentlyContinue) {
        Stop-Service $Service -Force -ErrorAction SilentlyContinue
        & sc.exe delete $Service | Out-Null
        Start-Sleep -Seconds 1
    }

    Log "[3/6] Installing files to $InstDir ..."
    New-Item -ItemType Directory -Force -Path $InstDir, $DataDir | Out-Null
    foreach ($f in $need) { Copy-Item (Join-Path $from $f) $InstDir -Force }
    foreach ($f in 'WinDivert-LICENSE.txt') {
        if (Test-Path (Join-Path $from $f)) { Copy-Item (Join-Path $from $f) $InstDir -Force }
    }
    foreach ($f in 'dpi-proxy-ctl.ps1', 'dpi-proxy-ctl.cmd', 'uninstall.ps1') {
        $p = Join-Path $Src $f
        if (-not (Test-Path $p)) { $p = Join-Path $from "scripts\windows\$f" }
        Copy-Item $p $InstDir -Force
    }
    $conf = Join-Path $DataDir 'strategy.conf'
    if (-not (Test-Path $conf)) {
        @(
            '# dpi-proxy manual rules. Transparent mode needs none: known-blocked'
            '# hosts (Discord and a few others, built in) get the bypass straight'
            '# away; any other host is tried directly first and learns a bypass only'
            '# if it needs one. Stream strategies: pass | tlsrec | tlsrec-split'
            '#'
            '# [domains]'
            '# example.com = tlsrec'
            'default = pass'
        ) | Set-Content -Encoding ASCII $conf
    }

    Log '[4/6] Firewall rule and PATH...'
    $exe = Join-Path $InstDir 'dpi-proxy.exe'
    # Redirected connections arrive at the service as inbound traffic;
    # the service itself refuses anything it did not redirect.
    Get-NetFirewallRule -Name $Service -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name $Service -DisplayName 'dpi-proxy (redirected local traffic)' `
        -Direction Inbound -Program $exe -Action Allow -Profile Any | Out-Null
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (($path -split ';') -notcontains $InstDir) {
        [Environment]::SetEnvironmentVariable('Path', "$path;$InstDir", 'Machine')
    }

    Log '[5/6] Creating and starting the service...'
    # New-Service, not sc.exe: PowerShell would mangle the quoted path
    New-Service -Name $Service -BinaryPathName "`"$exe`" --service" `
        -StartupType Automatic -DisplayName 'dpi-proxy (automatic DPI bypass)' `
        -Description 'Redirects outgoing HTTPS and DNS to a local DPI-bypass proxy (WinDivert). Stopping it restores ordinary networking.' | Out-Null
    & sc.exe failure $Service reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
    Remove-Item $StatusFile -ErrorAction SilentlyContinue
    Start-Service $Service

    Log '[6/6] Checking health...'
    $ok = $false
    foreach ($i in 1..40) {
        Start-Sleep -Milliseconds 500
        if ((Get-Service $Service).Status -eq 'Running' -and (Test-Path $StatusFile) -and
            (Select-String -Path $StatusFile -Pattern '^engine: running' -Quiet)) { $ok = $true; break }
    }
    if (-not $ok) { throw "service is not healthy; see $DataDir\dpi-proxy.log" }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    try { Resolve-DnsName example.com -Type A -ErrorAction Stop | Out-Null }
    catch { throw "name resolution through the service failed: $_" }
    try { Invoke-WebRequest -Uri 'https://example.com/' -UseBasicParsing -TimeoutSec 20 | Out-Null }
    catch { throw "HTTPS check through the service failed: $_" }
    $installed = $true
}
catch {
    Fail "$_"
    Fail 'stopping and removing the service (fail-open: networking returns to normal)'
    Stop-Service $Service -Force -ErrorAction SilentlyContinue
    & sc.exe delete $Service 2>$null | Out-Null
    exit 4
}

$other = Get-Process -Name goodbyedpi, winws -ErrorAction SilentlyContinue
Write-Host ''
Log 'Done. dpi-proxy is running and starts automatically at boot.'
Write-Host '  HTTPS and DNS from all applications now go through the automatic'
Write-Host '  bypass; no browser/app proxy settings and no DNS changes are needed.'
Write-Host ''
Write-Host '  Status:     dpi-proxy-ctl status        (open a new terminal first)'
Write-Host '  Logs:       dpi-proxy-ctl logs'
Write-Host '  Stop:       dpi-proxy-ctl stop          (networking keeps working, unbypassed)'
Write-Host "  Uninstall:  powershell -ExecutionPolicy Bypass -File `"$InstDir\uninstall.ps1`""
if ($other) {
    Write-Host ''
    Write-Host '  WARNING: another WinDivert-based DPI tool is running' -ForegroundColor Yellow
    Write-Host "  ($(($other | Select-Object -Expand Name -Unique) -join ', ')); stop it, the two will interfere." -ForegroundColor Yellow
}
