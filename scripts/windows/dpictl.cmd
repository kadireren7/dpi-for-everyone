@echo off
setlocal
rem PowerShell's own argument binder can swallow a bare "--verbose"/"-v"
rem token passed through -File (observed for real in CI: `dpictl status
rem --verbose` silently fell back to the short status). Detect it here,
rem in cmd.exe, where there is no such ambiguity, and hand it to the
rem script as an environment variable instead of relying on positional
rem binding of a dash-prefixed argument.
set DPICTL_VERBOSE=0
for %%A in (%*) do (
	if "%%~A"=="--verbose" set DPICTL_VERBOSE=1
	if "%%~A"=="-v" set DPICTL_VERBOSE=1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0dpictl-impl.ps1" %*
