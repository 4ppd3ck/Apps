// POSIX battery/vitals loop (macOS + Linux implementations), selected at
// runtime. Mirrors collectors/battery.py _macos / _linux / _linux_top_apps /
// _linux_volumes / _macos_extra_volumes. Only portable APIs are used here;
// the per-OS block-size helper (statVolume) lives in battery_darwin.go /
// battery_linux.go.
package collectors

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"monitor"
)

func (c *BatteryCollector) runPosix(interval float64) {
	c.SetStatus("active", "")
	for !c.Stopped() {
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.SetStatus("degraded", fmt.Sprintf("%v", r))
				}
			}()
			var info map[string]any
			if runtime.GOOS == "darwin" {
				info = c.collectMacOS()
			} else {
				info = c.collectLinux()
			}
			if info != nil {
				c.publish(info)
			}
		}()
		c.Sleep(interval)
	}
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// ------------------------------------------------------------- macOS ----

var (
	reTopCPU     = regexp.MustCompile(`CPU usage:\s*([\d.]+)%\s*user,\s*([\d.]+)%\s*sys,\s*([\d.]+)%\s*idle`)
	rePmsetBatt  = regexp.MustCompile(`(\d+)%;\s*([a-zA-Z ]+);(?:\s*(\d+):(\d+) remaining)?`)
	rePmsetLow   = regexp.MustCompile(`lowpowermode\s+(\d+)`)
	reMemFree    = regexp.MustCompile(`memory free percentage:\s*(\d+)%`)
	reAssertions = regexp.MustCompile(`pid\s+(\d+)\(([^)]*)\):[^\n]*?` +
		`((?:PreventUserIdleDisplaySleep|PreventUserIdleSystemSleep|` +
		`PreventSystemSleep|PreventDiskIdle))\s+named:\s*"([^"]*)"`)
)

func (c *BatteryCollector) collectMacOS() map[string]any {
	info := map[string]any{}
	// system CPU% (two `top` samples -> real instantaneous usage)
	_, topOut, _ := monitor.Run([]string{"top", "-l", "2", "-n", "0", "-s", "1"},
		25*time.Second)
	if uses := reTopCPU.FindAllStringSubmatch(topOut, -1); len(uses) > 0 {
		if idle, err := strconv.ParseFloat(uses[len(uses)-1][3], 64); err == nil {
			info["cpu_percent"] = round1(100.0 - idle)
		}
	}
	// disk usage: on APFS Macs `/` is the read-only system snapshot --
	// the user's data lives on the Data volume, so measure that one.
	dfPath := "/"
	if _, err := os.Stat("/System/Volumes/Data"); err == nil {
		dfPath = "/System/Volumes/Data"
	}
	_, dfOut, _ := monitor.Run([]string{"df", "-k", dfPath}, 6*time.Second)
	var lines []string
	for _, l := range strings.Split(dfOut, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	lines = lines[1:]
	if len(lines) > 0 {
		f := strings.Fields(lines[len(lines)-1])
		if len(f) >= 4 {
			used, err1 := strconv.ParseInt(f[2], 10, 64)
			avail, err2 := strconv.ParseInt(f[3], 10, 64)
			if err1 == nil && err2 == nil {
				total := used + avail
				if total > 0 {
					info["disk_percent"] = round1(float64(used) / float64(total) * 100)
					info["disk_used"] = fmt.Sprintf("%d GB", used/1048576)
					info["disk_total"] = fmt.Sprintf("%d GB", total/1048576)
				}
			}
		}
	}

	_, out, _ := monitor.Run([]string{"pmset", "-g", "batt"}, 6*time.Second)
	if m := rePmsetBatt.FindStringSubmatch(out); m != nil {
		pct, _ := strconv.Atoi(m[1])
		info["percent"] = pct
		info["state"] = strings.ToLower(strings.TrimSpace(m[2]))
		if m[3] != "" {
			info["time_remaining"] = fmt.Sprintf("%sh%s remaining", m[3], m[4])
		}
		_, low, _ := monitor.Run([]string{"pmset", "-g"}, 6*time.Second)
		if lm := rePmsetLow.FindStringSubmatch(low); lm != nil {
			info["low_power_mode"] = lm[1] == "1"
		}
	}

	// memory (RAM): the OS's own free-percentage calc, used/total derived
	_, mp, _ := monitor.Run([]string{"memory_pressure", "-Q"}, 8*time.Second)
	if fm := reMemFree.FindStringSubmatch(mp); fm != nil {
		_, memsize, _ := monitor.Run([]string{"sysctl", "-n", "hw.memsize"}, 5*time.Second)
		total, err1 := strconv.ParseInt(strings.TrimSpace(memsize), 10, 64)
		freePct, err2 := strconv.Atoi(fm[1])
		if err1 == nil && err2 == nil {
			info["mem_percent"] = 100 - freePct
			info["mem_total"] = fmt.Sprintf("%d GB", total/1073741824)
			info["mem_used"] = fmt.Sprintf("%d GB",
				total*int64(100-freePct)/100/1073741824)
		}
	}

	type appEntry struct {
		App     string  `json:"app"`
		CPU     float64 `json:"cpu"`
		Runtime string  `json:"runtime"`
	}
	var apps []appEntry
	_, psOut, _ := monitor.Run([]string{"ps", "-axo", "pid=,%cpu=,etime=,comm=", "-r"},
		8*time.Second)
	for _, line := range strings.Split(psOut, "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) < 4 {
			continue
		}
		// re-join the tail so comm with spaces survives (split(None, 4))
		if len(parts) > 5 {
			tail := strings.Join(parts[4:], " ")
			parts = append(parts[:4:4], tail)
		}
		pid, err1 := strconv.Atoi(parts[0])
		cpu, err2 := strconv.ParseFloat(parts[1], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if pid == os.Getpid() {
			continue
		}
		app := filepath.Base(strings.TrimSpace(parts[len(parts)-1]))
		if app == "kernel_task" || cpu < 0.5 {
			continue
		}
		apps = append(apps, appEntry{App: app, CPU: cpu, Runtime: parts[2]})
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].CPU > apps[j].CPU })
	if len(apps) > 8 {
		apps = apps[:8]
	}
	info["top_apps"] = apps

	type assertion struct {
		App    string `json:"app"`
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	var assertions []assertion
	seen := map[string]bool{}
	_, asm, _ := monitor.Run([]string{"pmset", "-g", "assertions"}, 8*time.Second)
	for _, am := range reAssertions.FindAllStringSubmatch(asm, -1) {
		app := am[2]
		if app == "" {
			app = am[1]
		}
		typ := strings.ReplaceAll(strings.ReplaceAll(am[3], "Prevent", ""), "Sleep", "-sleep")
		key := app + "\x00" + typ
		if seen[key] {
			continue
		}
		seen[key] = true
		assertions = append(assertions, assertion{App: app, Type: typ, Detail: am[4]})
	}
	if len(assertions) > 8 {
		assertions = assertions[:8]
	}
	info["assertions"] = assertions

	// all mounted volumes (external drives, USB sticks, other partitions)
	var vols []map[string]any
	if len(lines) > 0 {
		f := strings.Fields(lines[len(lines)-1])
		if len(f) >= 4 {
			used, err1 := strconv.ParseInt(f[2], 10, 64)
			avail, err2 := strconv.ParseInt(f[3], 10, 64)
			if err1 == nil && err2 == nil {
				total := used + avail
				if total > 0 {
					vols = append(vols, map[string]any{
						"name": "System (boot)", "path": dfPath,
						"percent": round1(float64(used) / float64(total) * 100),
						"used":    fmtGB(float64(used) * 1024),
						"total":   fmtGB(float64(total) * 1024),
						"boot":    true,
					})
				}
			}
		}
	}
	vols = append(vols, c.macosExtraVolumes()...)
	info["volumes"] = vols
	return info
}

// macosExtraVolumes lists real volumes under /Volumes (skips the symlinks
// that alias the boot volumes).
func (c *BatteryCollector) macosExtraVolumes() []map[string]any {
	var vols []map[string]any
	const volRoot = "/Volumes"
	entries, err := os.ReadDir(volRoot)
	if err != nil {
		return vols
	}
	for _, entry := range entries {
		path := filepath.Join(volRoot, entry.Name())
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		total, avail, ok := statVolume(path)
		if !ok || total <= 0 {
			continue
		}
		used := total - avail
		vols = append(vols, map[string]any{
			"name": entry.Name(), "path": path,
			"percent": round1(float64(used) / float64(total) * 100),
			"used":    fmtGB(float64(used)),
			"total":   fmtGB(float64(total)),
			"boot":    false,
		})
	}
	return vols
}

// -------------------------------------------------------------- Linux ---

func linuxBatteryDir() string {
	base := "/sys/class/power_supply"
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "BAT") {
			if fi, err := os.Stat(filepath.Join(base, entry.Name())); err == nil && fi.IsDir() {
				return filepath.Join(base, entry.Name())
			}
		}
	}
	return ""
}

func (c *BatteryCollector) collectLinux() map[string]any {
	bat := linuxBatteryDir()
	info := map[string]any{}
	// system CPU% from /proc/stat deltas between polls
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		first := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
		if len(first) > 1 {
			vals := first[1:]
			var sum int64
			nums := make([]int64, 0, len(vals))
			okParse := true
			for _, v := range vals {
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					okParse = false
					break
				}
				nums = append(nums, n)
				sum += n
			}
			if okParse && len(nums) >= 4 {
				idle := nums[3]
				if len(nums) > 4 {
					idle += nums[4]
				}
				prev := c.prevCPU
				c.prevCPU = [3]float64{float64(sum), float64(idle), monitor.Now()}
				if prev[2] != 0 && float64(sum) > prev[0] {
					didle := float64(idle) - prev[1]
					info["cpu_percent"] = round1(math.Max(0.0,
						100.0*(1-didle/(float64(sum)-prev[0]))))
				}
			}
		}
	}
	// root volume disk usage
	if total, avail, ok := statVolume("/"); ok && total > 0 {
		used := total - avail
		info["disk_percent"] = round1(float64(used) / float64(total) * 100)
		info["disk_used"] = fmt.Sprintf("%d GB", used/1073741824)
		info["disk_total"] = fmt.Sprintf("%d GB", total/1073741824)
	}
	// memory (RAM)
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		meminfo := map[string]int64{}
		for _, line := range strings.Split(string(data), "\n") {
			k, v, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			fields := strings.Fields(v)
			if len(fields) == 0 {
				continue
			}
			if n, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				meminfo[strings.TrimSpace(k)] = n // kB
			}
		}
		mt, ma := meminfo["MemTotal"], meminfo["MemAvailable"]
		if mt > 0 {
			used := mt - ma
			info["mem_percent"] = round1(float64(used) / float64(mt) * 100)
			info["mem_used"] = fmt.Sprintf("%d GB", used/1048576)
			info["mem_total"] = fmt.Sprintf("%d GB", mt/1048576)
		}
	}

	if bat != "" {
		read := func(name string) string {
			data, err := os.ReadFile(filepath.Join(bat, name))
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(data))
		}
		capacity, _ := strconv.ParseFloat(read("capacity"), 64)
		info["percent"] = int(capacity)
		state := read("status")
		if state == "" {
			state = "unknown"
		}
		info["state"] = strings.ToLower(state)
		now := read("energy_now")
		if now == "" {
			now = read("charge_now")
		}
		rate := read("power_now")
		if rate == "" {
			rate = read("current_now")
		}
		if now != "" && rate != "" {
			nowF, err1 := strconv.ParseFloat(now, 64)
			rateF, err2 := strconv.ParseFloat(rate, 64)
			if err1 == nil && err2 == nil && rateF != 0 {
				hours := nowF / rateF
				stateStr, _ := info["state"].(string)
				if strings.HasPrefix(stateStr, "disch") && hours > 0 && hours < 48 {
					totalMin := int(hours * 60)
					h := totalMin / 60
					m := totalMin % 60
					info["time_remaining"] = fmt.Sprintf("%dh%02d remaining", h, m)
				}
			}
		}
	}
	info["top_apps"] = c.linuxTopApps()
	info["volumes"] = c.linuxVolumes()
	return info
}

func (c *BatteryCollector) linuxVolumes() []map[string]any {
	var vols []map[string]any
	seen := map[string]bool{}
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return vols
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		dev := parts[0]
		mnt := strings.ReplaceAll(parts[1], "\\040", " ")
		fstype := parts[2]
		if !strings.HasPrefix(dev, "/dev/") || fstype == "swap" || fstype == "squashfs" {
			continue
		}
		if seen[dev] {
			continue
		}
		total, avail, ok := statVolume(mnt)
		if !ok || total <= 0 {
			continue
		}
		seen[dev] = true
		used := total - avail
		name := filepath.Base(dev)
		if mnt != "/" {
			name += " → " + mnt
		}
		vols = append(vols, map[string]any{
			"name": name, "path": mnt,
			"percent": round1(float64(used) / float64(total) * 100),
			"used":    fmtGB(float64(used)),
			"total":   fmtGB(float64(total)),
			"boot":    mnt == "/",
		})
	}
	return vols
}

var linuxPrevJiffies = map[int][2]float64{} // per collector instance below

func (c *BatteryCollector) linuxTopApps() []map[string]any {
	const hz = 100.0 // SC_CLK_TCK on stock Linux kernels
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return []map[string]any{}
	}
	uptime, err2 := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	if err2 != nil {
		return []map[string]any{}
	}
	now := monitor.Now()
	type sampleEntry struct {
		comm      string
		jiffies   int64
		starttime int64
	}
	sample := map[int]sampleEntry{}
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if !isAllDigits(entry.Name()) {
			continue
		}
		pid, _ := strconv.Atoi(entry.Name())
		stat, err1 := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		comm, err2 := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err1 != nil || err2 != nil {
			continue
		}
		commStr := strings.TrimSpace(string(comm))
		if pid == os.Getpid() || strings.HasPrefix(commStr, "(") {
			continue // kernel threads
		}
		after := stat
		if idx := strings.LastIndex(string(stat), ")"); idx >= 0 {
			after = stat[idx+1:]
		}
		fields := strings.Fields(string(after))
		if len(fields) < 22 {
			continue
		}
		utime, _ := strconv.ParseInt(fields[11], 10, 64)
		stime, _ := strconv.ParseInt(fields[12], 10, 64)
		starttime, _ := strconv.ParseInt(fields[19], 10, 64)
		sample[pid] = sampleEntry{commStr, utime + stime, starttime}
	}
	var apps []map[string]any
	for pid, s := range sample {
		prev, ok := c.prevJiffies[pid]
		c.prevJiffies[pid] = [2]float64{float64(s.jiffies), now}
		if !ok || now-prev[1] < 0.5 {
			continue
		}
		cpu := (float64(s.jiffies) - prev[0]) / hz / (now - prev[1]) * 100
		if cpu < 0.5 {
			continue
		}
		runtime := math.Max(uptime-float64(s.starttime)/hz, 0)
		totalSec := int(runtime)
		h := totalSec / 3600
		rem := totalSec % 3600
		m := rem / 60
		sec := rem % 60
		var rt string
		if h >= 24 {
			rt = fmt.Sprintf("%dd%02d:%02d", h, m, sec)
		} else if h > 0 {
			rt = fmt.Sprintf("%d:%02d:%02d", h, m, sec)
		} else {
			rt = fmt.Sprintf("%02d:%02d", m, sec)
		}
		name := s.comm
		if len(name) > 40 {
			name = name[:40]
		}
		apps = append(apps, map[string]any{
			"app": name, "cpu": round1(cpu), "runtime": rt})
	}
	if len(c.prevJiffies) > 4096 {
		c.prevJiffies = map[int][2]float64{}
	}
	sort.Slice(apps, func(i, j int) bool {
		a, _ := apps[i]["cpu"].(float64)
		b, _ := apps[j]["cpu"].(float64)
		return a > b
	})
	if len(apps) > 8 {
		apps = apps[:8]
	}
	return apps
}
