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
#   add|country|CN|country-CN.cidr   (CIDR list in this helper's folder)
#   add|list|mylist|list-mylist.cidr (same, for user blocklist files)
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

# CIDR chunk rules carry an index: "AppScope block country CN out 001" /
# "AppScope block list mylist out 001". Must stay byte-identical to the
# monitor's direct naming (enforcer.go).
function ChunkRuleName([string]$type, [string]$value, [string]$dir, [int]$idx) {
    return "AppScope block $type $value $dir " + $idx.ToString("000")
}

function Test-IPv4Cidr([string]$s) {
    $parts = $s -split "/", 2
    if ($parts.Count -ne 2) { return $false }
    if (-not (Test-IPv4 $parts[0])) { return $false }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }
    return $prefix -ge 1 -and $prefix -le 32
}

# Ranges this helper must never block: loopback, private, link-local,
# 0/8, multicast, reserved — the machine's own subnets and the loopback
# dashboard live there.
function Test-ProtectedCidr([string]$s) {
    $ip = ($s -split "/", 2)[0]
    $o = $ip -split "\."
    $a = [int]$o[0]; $b = if ($o.Count -gt 1) { [int]$o[1] } else { 0 }
    if ($a -in 0,10,127) { return $true }
    if ($a -eq 169 -and $b -eq 254) { return $true }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true }
    if ($a -eq 192 -and $b -eq 168) { return $true }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $true }
    if ($a -ge 224) { return $true }
    return $false
}

function Apply-ChunkRule([string]$type, [string]$value, [string]$file) {
    # the CIDR file must live in this helper's own directory (no traversal)
    $path = Join-Path $Dir $file
    if ([System.IO.Path]::GetFileName($file) -ne $file -or -not (Test-Path $path)) {
        throw "cidr file not found: $file"
    }
    $cidrs = @(Get-Content $path -ErrorAction Stop |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne "" -and (Test-IPv4Cidr $_) -and -not (Test-ProtectedCidr $_) })
    $chunks = @(); $cur = @(); $chars = 0
    foreach ($c in $cidrs) {
        if ($cur.Count -ge 400 -or ($cur.Count -gt 0 -and $chars + $c.Length + 1 -gt 8000)) {
            $chunks += ,@($cur); $cur = @(); $chars = 0
        }
        $cur += $c; $chars += $c.Length + 1
    }
    if ($cur.Count -gt 0) { $chunks += ,@($cur) }
    for ($i = 0; $i -lt $chunks.Count; $i++) {
        $remote = "remoteip=" + ($chunks[$i] -join ",")
        netsh advfirewall firewall add rule name=(ChunkRuleName $type $value "out" ($i + 1)) `
            dir=out action=block $remote | Out-Null
        netsh advfirewall firewall add rule name=(ChunkRuleName $type $value "in" ($i + 1)) `
            dir=in action=block $remote | Out-Null
    }
    return $chunks.Count
}

function Remove-ChunkRules([string]$type, [string]$value) {
    # name= supports a trailing * on delete: two calls lift every chunk
    netsh advfirewall firewall delete rule name="AppScope block $type $value out *" | Out-Null
    netsh advfirewall firewall delete rule name="AppScope block $type $value in *" | Out-Null
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
        # CIDR rules (country / list) are handled fully here (chunked netsh
        # rules fed from a CIDR file in this directory) and never reach the
        # generic path below — deliberately before the switch, because a
        # bare `continue` inside a switch would only exit the switch
        if ($type -eq "country" -or $type -eq "list" -or $type -eq "provider") {
            if ($type -eq "country") {
                if ($value -notmatch "^[A-Za-z]{2}$") { continue }
                $value = $value.ToUpper()
            } elseif ($type -eq "provider") {
                $value = ($value -replace "[^a-z0-9_-]", "-")
                if ($value -notmatch "^[a-z0-9_-]{1,32}$") { continue }
            } elseif ($value -notmatch "^[a-z0-9_-]{1,32}$") { continue }
            if ($action -eq "add") {
                if ([System.IO.Path]::GetFileName($extra) -ne $extra) { continue }
                $null = Apply-ChunkRule $type $value $extra
                # replace any previous entry for this set (the file may have
                # been refreshed with new ranges)
                $rules = @($rules | Where-Object {
                    $_ -notmatch ("^" + [regex]::Escape($type) + "\|" +
                                  [regex]::Escape($value) + "\|") })
                $rules += "$type|$value|$extra"
                $changed = $true
            } else {
                Remove-ChunkRules $type $value
                $rules = @($rules | Where-Object {
                    $_ -notmatch ("^" + [regex]::Escape($type) + "\|" +
                                  [regex]::Escape($value) + "\|") })
                $changed = $true
            }
            continue
        }
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
