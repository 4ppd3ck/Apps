@echo off
rem Descale server launcher (Windows). Expects a platform binary next to
rem this script (descale-windows-amd64.exe); build with Go if absent.
setlocal
cd /d "%~dp0"
if exist descale-windows-amd64.exe (
  descale-windows-amd64.exe %1
) else (
  echo Windows binary not found; build with: go build -o descale-windows-amd64.exe .
  exit /b 1
)
