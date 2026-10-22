@echo off
:: GamingTweaks - opens the window (GUI). Add -Console for the text menu.
if /i "%~1"=="-Console" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0GamingTweaks.ps1" -Console
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File "%~dp0GamingTweaks.ps1"
)
