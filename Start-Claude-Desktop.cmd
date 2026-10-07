@echo off
powershell.exe -NoProfile -File "%~dp0ClaudeGuard.ps1" -Mode Launch -Client Desktop %*
if errorlevel 1 pause
