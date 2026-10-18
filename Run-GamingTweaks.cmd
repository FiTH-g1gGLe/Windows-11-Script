@echo off
:: Starts GamingTweaks.ps1 (it asks for admin itself) without changing your PowerShell execution policy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0GamingTweaks.ps1"
