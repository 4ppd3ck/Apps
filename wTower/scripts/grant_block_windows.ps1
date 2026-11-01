# Grant AppScope Monitor permission to enforce connection/IP/app blocks
# without running the whole monitor elevated (Windows).
#
#   powershell -ExecutionPolicy Bypass -File scripts\grant_block_windows.ps1           # install
#   powershell -ExecutionPolicy Bypass -File scripts\grant_block_windows.ps1 -Revoke   # remove
#
# Run this from an unelevated shell and it re-launches itself with the UAC
# elevation dialog (the dashboard's Grant button does exactly that through
# Start-Process -Verb RunAs; approve once).
#
# What this installs:
#   C:\ProgramData\AppScopeBlock\appscope-block-helper.ps1
#       validating SYSTEM helper: applies BLOCK-only netsh rules from a
#       queue of command files, keeps the applied set in rules.txt.
#   C:\ProgramData\AppScopeBlock\queue\   writable by Users (the monitor
#       drops add/del commands here; only the helper executes them).
#       ACLs are explicit (inheritance disabled): nothing else under
#       AppScopeBlock is user-writable.
#   Scheduled task "AppScopeBlock" (SYSTEM, highest privileges) running the
#       helper -- the monitor triggers it with schtasks /run, never elevating.
#
# The helper can only ADD or REMOVE firewall BLOCK rules through strict
# argument validation -- it cannot open ports or change anything else.
param([switch]$Revoke)
$ErrorActionPreference = "Stop"

$Dir = Join-Path $env:ProgramData "AppScopeBlock"
$TaskName = "AppScopeBlock"

# Elevation self-relaunch: if not admin, spawn an elevated copy and exit.
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
    if ($Revoke) { $args += "-Revoke" }
    Start-Process powershell -Verb RunAs -Wait -ArgumentList $args
    exit $LASTEXITCODE
}

function Remove-AllRules {
    $rulesPath = Join-Path $Dir "rules.txt"
    if (Test-Path $rulesPath) {
        foreach ($line in Get-Content $rulesPath) {
            $p = $line -split "\|", 3
            if ($p.Count -lt 2 -or $p[0] -eq "") { continue }

            if ($p[0] -eq "country" -or $p[0] -eq "list" -or $p[0] -eq "provider") {
                # chunk rules carry a numbered suffix: lift them all at once
                netsh advfirewall firewall delete rule `
                    name="AppScope block country $($p[1]) out *" | Out-Null
                netsh advfirewall firewall delete rule `
                    name="AppScope block country $($p[1]) in *" | Out-Null
                continue
            }
            netsh advfirewall firewall delete rule `
                name="AppScope block $($p[0]) $($p[1]) out" | Out-Null
            netsh advfirewall firewall delete rule `
                name="AppScope block $($p[0]) $($p[1]) in" | Out-Null
        }
    }
}

if ($Revoke) {
    Remove-AllRules
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "Revoked: AppScopeBlock task, helper and firewall rules removed."
    exit 0
}

New-Item -ItemType Directory -Force -Path (Join-Path $Dir "queue") | Out-Null
Copy-Item (Join-Path $PSScriptRoot "appscope-block-helper.ps1") `
    (Join-Path $Dir "appscope-block-helper.ps1") -Force
# Explicit ACLs only -- inheritance from ProgramData is disabled so a
# standard user cannot create or replace anything in the broker tree.
# SYSTEM and Administrators own everything; the unelevated monitor gets
# write access to the queue ONLY (Users via well-known SID), never to the
# helper or rules.txt.
icacls $Dir /inheritance:r | Out-Null
icacls $Dir /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
icacls (Join-Path $Dir "queue") /inheritance:r | Out-Null
icacls (Join-Path $Dir "queue") /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" `
    "*S-1-5-32-545:(OI)(CI)M" | Out-Null

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dir\appscope-block-helper.ps1`" -ProcessQueue"
$principalSys = New-ScheduledTaskPrincipal -UserId "S-1-5-18" `
    -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $TaskName -Action $action `
    -Principal $principalSys -Settings $settings -Force | Out-Null

# smoke-test the task end to end
Start-ScheduledTask -TaskName $TaskName
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    $state = (Get-ScheduledTask -TaskName $TaskName).State
    if ($state -eq "Ready") { break }
    Start-Sleep -Milliseconds 500
}

Write-Output "Installed:"
Write-Output "  $Dir\appscope-block-helper.ps1  (validating BLOCK-only firewall helper)"
Write-Output "  scheduled task $TaskName (SYSTEM) triggered by the monitor via schtasks /run"
Write-Output "Next: click 're-apply' on the Blocked panel (or restart the monitor)"
Write-Output "to activate any queued blocks. Revoke: $PSCommandPath -Revoke"
