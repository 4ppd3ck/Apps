// Windows battery/vitals loop: one persistent PowerShell that prints a JSON
// snapshot (battery, CPU, disks, memory, volumes, top consumers) every 8s.
// Mirrors collectors/battery.py _run_windows + _PS_SCRIPT. Uses only
// portable APIs (exec + JSON), so it is compiled on every platform and
// selected at runtime by BatteryCollector.run.
package collectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"monitor"
)

// runPowerShellProbe mirrors the powershell availability probe.
func runPowerShellProbe() (int, string, string) {
	return monitor.Run([]string{"powershell.exe", "-NoProfile", "-Command",
		"$null"}, 15*time.Second)
}

const batteryPS = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
while ($true) {
  $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue |
           Select-Object -First 1
  $percent = $null; $state = 'no battery'
  if ($bat) {
    $percent = [int]$bat.EstimatedChargeRemaining
    $state = if ($bat.BatteryStatus -eq 2) { 'charging' }
             elseif ($bat.BatteryStatus -eq 1) { 'discharging' }
             else { "status $($bat.BatteryStatus)" }
  }
  $cpuSum = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
             Measure-Object -Property LoadPercentage -Average).Average
  $cpuFromLoad = if ($null -ne $cpuSum) { [math]::Round([double]$cpuSum, 1) } else { $null }
  $diskpct = $null; $diskused = $null; $disktotal = $null
  $vols = @()
  Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
    ForEach-Object {
      $t = $_.Used + $_.Free
      if ($t -gt 1GB) {
        $pct = [math]::Round(100 * $_.Used / $t, 1)
        $vols += @{name = ($_.Name + ':'); path = $_.Root; percent = $pct;
                   used = ('{0} GB' -f [int]($_.Used / 1GB));
                   total = ('{0} GB' -f [int]($t / 1GB));
                   boot = ($_.Name -eq 'C')}
        if ($_.Name -eq 'C') {
          $diskpct = $pct
          $diskused = '{0} GB' -f [int]($_.Used / 1GB)
          $disktotal = '{0} GB' -f [int]($t / 1GB)
        }
      }
    }
  $mempct = $null; $memused = $null; $memtotal = $null
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
  if ($os) {
    $mt = [double]$os.TotalVisibleMemorySize
    $mf = [double]$os.FreePhysicalMemory
    if ($mt -gt 0) {
      $mempct = [math]::Round(100 * (1 - $mf / $mt), 1)
      $memused = '{0} GB' -f [int](($mt - $mf) / 1MB)
      $memtotal = '{0} GB' -f [int]($mt / 1MB)
    }
  }
  $s1 = @{}
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Id -ne $PID -and $_.TotalProcessorTime) {
      $s1[$_.Id] = $_.TotalProcessorTime.TotalSeconds
    }
  }
  Start-Sleep -Seconds 1
  $cores = [Environment]::ProcessorCount
  $totalDelta = 0.0
  $apps = @()
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Id -ne $PID -and $_.TotalProcessorTime) {
      $prev = 0
      if ($s1.ContainsKey($_.Id)) { $prev = $s1[$_.Id] }
      $cpu = $_.TotalProcessorTime.TotalSeconds - $prev
      if ($cpu -ge 0) { $totalDelta += $cpu }
      if ($cpu -ge 0.01) {
        $rt = '-'
        try {
          if ($_.StartTime) {
            $ts = (Get-Date) - $_.StartTime
            $rt = '{0}:{1:mm\:ss}' -f [int]$ts.TotalHours, $ts
          }
        } catch {
          $rt = '-'
        }
        $cpuPct = 100 * $cpu / [math]::Max(1, $cores)
        $apps += @{app = $_.ProcessName; cpu = [math]::Round($cpuPct, 1); runtime = $rt}
      }
    }
  }
  # system-wide CPU% from summed process deltas (works on all hardware);
  # fall back to LoadPercentage only when the delta path yields nothing
  $cpu = [math]::Round([math]::Min(100,
    100 * $totalDelta / ([math]::Max(1, $cores) * 1.0)), 1)
  if ($null -ne $cpuFromLoad -and $totalDelta -le 0) { $cpu = $cpuFromLoad }
  $apps = @($apps | Sort-Object { $_.cpu } -Descending | Select-Object -First 8)
  @{percent = $percent; state = $state; cpu = $cpu; diskpct = $diskpct;
    diskused = $diskused; disktotal = $disktotal; mempct = $mempct;
    memused = $memused; memtotal = $memtotal; vols = $vols;
    apps = @($apps)} |
    ConvertTo-Json -Depth 3 -Compress | Write-Output
  [Console]::Out.Flush()
  Start-Sleep -Seconds 8
}
`

func (c *BatteryCollector) runWindows(_ float64) {
	script := filepath.Join(os.TempDir(), "appscope_batt.ps1")
	if err := os.WriteFile(script, []byte(batteryPS), 0o644); err != nil {
		c.SetStatus("unavailable", "cannot write helper script: "+err.Error())
		return
	}
	proc, reader, err := monitor.PopenStream([]string{"powershell.exe", "-NoProfile",
		"-ExecutionPolicy", "Bypass", "-File", script})
	if err != nil {
		c.SetStatus("unavailable", "powershell.exe not found")
		return
	}
	c.registerProc(proc)
	c.SetStatus("active", "")
	for {
		line, readErr := reader.ReadString('\n')
		if c.Stopped() {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			var info map[string]any
			if json.Unmarshal([]byte(line), &info) == nil {
				c.normalizeWindows(info)
				c.publish(info)
			}
		}
		if readErr != nil {
			break
		}
	}
}

// normalizeWindows applies the key aliases the Python loop maps over.
func (c *BatteryCollector) normalizeWindows(info map[string]any) {
	if info["cpu_percent"] == nil {
		info["cpu_percent"] = info["cpu"]
	}
	if info["disk_percent"] == nil {
		info["disk_percent"] = info["diskpct"]
	}
	if info["disk_used"] == nil {
		info["disk_used"] = info["diskused"]
	}
	if info["disk_total"] == nil {
		info["disk_total"] = info["disktotal"]
	}
	if info["mem_percent"] == nil {
		info["mem_percent"] = info["mempct"]
	}
	if info["mem_used"] == nil {
		info["mem_used"] = info["memused"]
	}
	if info["mem_total"] == nil {
		info["mem_total"] = info["memtotal"]
	}
	if len(jsonList(info["volumes"])) == 0 {
		info["volumes"] = jsonList(info["vols"])
	}
	apps := jsonList(info["top_apps"])
	if len(apps) == 0 {
		apps = jsonList(info["apps"])
	}
	info["top_apps"] = apps
}

// jsonList mirrors Python's _as_list-ish handling of PowerShell arrays that
// collapse to a single object: nil -> [], []any -> itself, object -> [object].
func jsonList(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	default:
		return []any{x}
	}
}
