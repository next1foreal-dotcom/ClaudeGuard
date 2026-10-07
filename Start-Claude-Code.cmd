@echo off
powershell.exe -NoProfile -File "%~dp0ClaudeGuard.ps1" -Mode Launch -Client Code %*
if errorlevel 1 pause
