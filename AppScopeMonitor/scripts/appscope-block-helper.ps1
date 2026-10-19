# appscope-block -- privileged helper used by AppScope Monitor to enforce
# connection/IP/app blocks on Windows. Installed into C:\ProgramData\AppScopeBlock
# by scripts\grant_block_windows.ps1 (elevated, one UAC prompt) and registered
# as the scheduled task "AppScopeBlock" running as SYSTEM. The unelevated
# monitor drops command files into the queue/ folder and starts the task; it
# can never elevate itself.
#
#   appscope-block-helper.ps1 -ProcessQueue     (task action: apply queued adds/dels)
#   appscope-block-helper.ps1 -Status           (print active rule count)
#
# Queue files are one command each:  <action>|<type>|<value>|<extra>
#   add|ip|203.0.113.7|
#   add|connection|203.0.113.7:443|
#   add|app|evil.exe|C:\path\evil.exe
#   del|...
# Applied rules persist in rules.txt as  <type>|<value>|<extra>  and are
# re-applied verbatim on every queue run, so a reboot loses nothing.
#
# All arguments are strictly validated (IPv4 parse, numeric ports, absolute
# existing paths, no pipe characters). The netsh rules generated here can
# only BLOCK (action=block) -- the helper can never open or forward anything.
param(
    [switch]$ProcessQueue,
    [switch]$Status
)
$ErrorActionPreference = "Stop"

$Dir = Join-Path $env:ProgramData "AppScopeBlock"
$RulesPath = Join-Path $Dir "rules.txt"
$QueueDir = Join-Path $Dir "queue"

function Test-IPv4([string]$s) {
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($s, [ref]$ip)) { return $false }
    return $ip.AddressFamily -eq [System.Net.AddressFamily]::InterNetwork
}

# Rule names must stay byte-identical to the monitor's direct (elevated)
# naming: "AppScope block <type> <value> <dir>".
function RuleName([string]$type, [string]$value, [string]$dir) {
    return "AppScope block $type $value $dir"
}

function Apply-Rule([string]$type, [string]$value, [string]$extra) {
    if ($type -eq "app") {
        netsh advfirewall firewall add rule name=(RuleName $type $value "out") `
            dir=out action=block program="$extra" | Out-Null
        netsh advfirewall firewall add rule name=(RuleName $type $value "in") `
            dir=in action=block program="$extra" | Out-Null
    } else {
        $parts = $value -split ":", 2
        $extraArgs = @("remoteip=" + $parts[0])
        if ($parts.Count -gt 1 -and $parts[1] -ne "") {
            $extraArgs += "remoteport=" + $parts[1]
        }
        netsh advfirewall firewall add rule name=(RuleName $type $value "out") `
            dir=out action=block @extraArgs | Out-Null
        netsh advfirewall firewall add rule name=(RuleName $type $value "in") `
            dir=in action=block @extraArgs | Out-Null
    }
}

function Remove-Rule([string]$type, [string]$value) {
    netsh advfirewall firewall delete rule name=(RuleName $type $value "out") | Out-Null
    netsh advfirewall firewall delete rule name=(RuleName $type $value "in") | Out-Null
}

if ($Status) {
    $n = 0
    if (Test-Path $RulesPath) { $n = (Get-Content $RulesPath | Measure-Object).Count }
    Write-Output "active rules: $n"
    exit 0
}

if (-not $ProcessQueue) {
    Write-Output "usage: appscope-block-helper.ps1 [-ProcessQueue|-Status]"
    exit 2
}

New-Item -ItemType Directory -Force -Path $QueueDir | Out-Null
if (-not (Test-Path $RulesPath)) { New-Item -ItemType File -Path $RulesPath | Out-Null }
$rules = @(Get-Content $RulesPath -ErrorAction SilentlyContinue | Where-Object { $_ -ne "" })

$changed = $false
foreach ($f in @(Get-ChildItem -Path $QueueDir -Filter "*.cmd" -ErrorAction SilentlyContinue | Sort-Object Name)) {
    $line = (Get-Content $f.FullName -TotalCount 1 -ErrorAction SilentlyContinue)
    Remove-Item $f.FullName -Force
    if (-not $line) { continue }
    $p = $line.Trim() -split "\|", 4
    if ($p.Count -lt 3) { continue }
    $action, $type, $value = $p[0], $p[1], $p[2]
    $extra = ""
    if ($p.Count -gt 3) { $extra = $p[3] }

    try {
        switch ($type) {
            "ip" {
                if (-not (Test-IPv4 $value)) { continue }
                $entry = "ip|$value|"
            }
            "connection" {
                $parts = $value -split ":", 2
                if ($parts.Count -ne 2 -or -not (Test-IPv4 $parts[0])) { continue }
                $port = 0
                if (-not [int]::TryParse($parts[1], [ref]$port) -or
                    $port -lt 1 -or $port -gt 65535) { continue }
                $entry = "connection|$value|"
            }
            "app" {
                if (-not [System.IO.Path]::IsPathRooted($extra) -or
                    -not (Test-Path $extra) -or $extra -match "\|") { continue }
                $entry = "app|$value|$extra"
            }
            default { continue }
        }
        if ($action -eq "add") {
            if ($rules -notcontains $entry) {
                $rules += $entry
                $changed = $true
            }
            Apply-Rule $type $value $extra
        } elseif ($action -eq "del") {
            if ($rules -contains $entry) {
                $rules = @($rules | Where-Object { $_ -ne $entry })
                $changed = $true
            }
            Remove-Rule $type $value
        }
    } catch {
        # one bad command must not block the rest of the queue
        continue
    }
}

if ($changed) {
    Set-Content -Path $RulesPath -Value $rules -Encoding ASCII
}
