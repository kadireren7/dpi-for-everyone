@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0dpi-proxy-ctl.ps1" %*
