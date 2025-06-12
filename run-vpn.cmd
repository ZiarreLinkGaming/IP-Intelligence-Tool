@echo off
setlocal

set "scriptDir=%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%scriptDir%VPN.ps1"

endlocal
