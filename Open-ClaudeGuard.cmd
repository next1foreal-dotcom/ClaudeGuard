@echo off
powershell.exe -NoProfile -STA -File "%~dp0ClaudeGuardUI.ps1"
if errorlevel 1 pause
