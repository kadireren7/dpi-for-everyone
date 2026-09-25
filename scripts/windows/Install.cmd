@echo off
setlocal
rem dpi-for-everyone: double-click installer for Windows.
rem
rem Elevates itself (a UAC prompt appears) and runs install.ps1 from
rem this same folder, then keeps the window open so you can read the
rem result. For manual or scripted installs, run install.ps1 directly
rem instead (see WINDOWS-QUICKSTART.txt).

rem "net session" only succeeds for an already-elevated process; it is
rem the standard, dependency-free way to test for administrator rights
rem from a batch file.
net session >nul 2>&1
if %errorlevel% == 0 goto :run

echo dpi-for-everyone needs administrator rights to install a service.
echo A User Account Control prompt will appear - choose Yes.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
	"Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
exit /b 0

:run
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\install.ps1"
echo.
echo Press any key to close this window...
pause >nul
