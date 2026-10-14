// Application context shared by collectors, server and store
// (mirrors monitor/context.py).
package monitor

import "sync"

// Status is a collector status chip: {"state": ..., "detail": ...}
// (base.Collector.status dict).
type Status struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// Collector is the collector contract (base.py's Collector base class).
// The concrete implementations live in the collectors subpackage; the
// interface lives here because Ctx carries the collector set and the
// collectors package imports this one.
type Collector interface {
	Name() string
	Description() string
	Category() string
	Status() Status
	SetStatus(state, detail string)
	Enabled() bool
	SetEnabled(enabled bool)
	Available() (bool, string)
	Start()
	Stop()
	Run()
	Stopped() bool
	Sleep(seconds float64)
	Emit(ev *Event)
}

// Ctx bundles config, store, event bus and shared live state.
type Ctx struct {
	Cfg      *Config
	Store    *Store
	Bus      *EventBus
	Net      *NetState
	Enforcer *Enforcer

	collectors []Collector

	androidMu      sync.Mutex
	androidDevices []string

	batteryMu sync.Mutex
	battery   map[string]any
}

// NewCtx creates the application context.
func NewCtx(cfg *Config, store *Store, bus *EventBus) *Ctx {
	return &Ctx{
		Cfg:            cfg,
		Store:          store,
		Bus:            bus,
		Net:            NewNetState(240),
		androidDevices: []string{},
	}
}

// Collectors returns the collector set.
func (c *Ctx) Collectors() []Collector { return c.collectors }

// SetCollectors installs the collector set (called once at startup).
func (c *Ctx) SetCollectors(cols []Collector) { c.collectors = cols }

// Poll returns a poll interval from the config (cfg["poll"].get(name, def)).
func (c *Ctx) Poll(name string, def float64) float64 { return c.Cfg.Poll(name, def) }

// WatchedDirs returns the configured watched directories.
func (c *Ctx) WatchedDirs() []string { return c.Cfg.WatchedDirs() }

// GetString returns a string config setting (cfg.get(key, def)).
func (c *Ctx) GetString(key, def string) string { return c.Cfg.GetString(key, def) }

// GetBool returns a boolean config setting.
func (c *Ctx) GetBool(key string, def bool) bool { return c.Cfg.GetBool(key, def) }

// AndroidDevices returns the last known adb device serials.
func (c *Ctx) AndroidDevices() []string {
	c.androidMu.Lock()
	defer c.androidMu.Unlock()
	out := make([]string, len(c.androidDevices))
	copy(out, c.androidDevices)
	return out
}

// SetAndroidDevices records the current adb device serials.
func (c *Ctx) SetAndroidDevices(serials []string) {
	c.androidMu.Lock()
	c.androidDevices = serials
	c.androidMu.Unlock()
}

// Battery returns a copy of the latest battery/power snapshot (may be nil).
func (c *Ctx) Battery() map[string]any {
	c.batteryMu.Lock()
	defer c.batteryMu.Unlock()
	if c.battery == nil {
		return nil
	}
	out := make(map[string]any, len(c.battery))
	for k, v := range c.battery {
		out[k] = v
	}
	return out
}

// SetBattery replaces the latest battery/power snapshot.
func (c *Ctx) SetBattery(info map[string]any) {
	c.batteryMu.Lock()
	c.battery = info
	c.batteryMu.Unlock()
}
