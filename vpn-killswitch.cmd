@echo off
rem Launcher: runs vpn-killswitch.ps1 without changing the PowerShell execution policy.
rem Usage: vpn-killswitch.cmd --start 203.0.113.10 [--allow-lan] | --stop | --status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0vpn-killswitch.ps1" %*
exit /b %ERRORLEVEL%
