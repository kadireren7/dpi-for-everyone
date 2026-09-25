@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0dpictl-impl.ps1" %*
