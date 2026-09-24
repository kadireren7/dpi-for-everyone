#Requires -Version 5.1
<#
.SYNOPSIS
  Removes everything install.ps1 installed: the "dpi-proxy" service,
  %ProgramFiles%\dpi-proxy, its firewall rule and PATH entry, and the
  WinDivert driver service if no other program is using it.
  %ProgramData%\dpi-proxy (your manual rules, learned decisions, log)
  is kept unless -Purge is given. Needs an elevated PowerShell.
#>
[CmdletBinding()]
param([switch]$Purge)

$ErrorActionPreference = 'Continue'
$Service = 'dpi-proxy'
$InstDir = Join-Path $env:ProgramFiles 'dpi-proxy'
$DataDir = Join-Path $env:ProgramData 'dpi-proxy'

function Log($m) { Write-Host "[uninstall] $m" }

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[uninstall] ERROR: needs an elevated (Administrator) PowerShell.' -ForegroundColor Red
    exit 1
}

if (Get-Service $Service -ErrorAction SilentlyContinue) {
    Log 'stopping and removing the service'
    Stop-Service $Service -Force -ErrorAction SilentlyContinue
    & sc.exe delete $Service | Out-Null
}
Get-NetFirewallRule -Name $Service -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$kept = ($path -split ';') | Where-Object { $_ -and $_ -ne $InstDir }
[Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')

# The WinDivert driver is shared by every WinDivert-based program; only
# unload it if nothing else is using it (otherwise Windows removes it at
# the next reboot, once no program loads it any more).
$other = Get-Process -Name goodbyedpi, winws -ErrorAction SilentlyContinue
if (-not $other -and (Get-Service WinDivert -ErrorAction SilentlyContinue)) {
    Log 'unloading the WinDivert driver'
    & sc.exe stop WinDivert | Out-Null
    & sc.exe delete WinDivert | Out-Null
} elseif ($other) {
    Log 'another WinDivert program is running; leaving the driver loaded'
}

if (Test-Path $InstDir) {
    Log "removing $InstDir"
    # this script may be running from there: remove everything else first
    Get-ChildItem $InstDir | Where-Object { $_.FullName -ne $PSCommandPath } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    if ($PSCommandPath -and $PSCommandPath.StartsWith($InstDir)) {
        Start-Process -WindowStyle Hidden cmd.exe "/c timeout /t 2 >nul & rmdir /s /q `"$InstDir`""
    } else {
        Remove-Item $InstDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if ($Purge) {
    Log "removing $DataDir"
    Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
} elseif (Test-Path $DataDir) {
    Log "kept $DataDir (manual rules, learned decisions, log); -Purge removes it"
}
Log 'done; networking is back to normal'
