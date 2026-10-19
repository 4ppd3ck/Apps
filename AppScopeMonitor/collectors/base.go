// Collector base contract shared by all collectors.
//
// base.py defines the Collector base class; here the interface itself lives
// in the root monitor package (Ctx carries []Collector, and the collectors
// package imports monitor, so the interface cannot live in this package
// without an import cycle). monitor.Collector is re-exported below, and
// BaseCollector provides the default implementation of every method except
// the collector's own run loop.
package collectors

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"monitor"
)

// Collector mirrors base.Collector.
type Collector = monitor.Collector

// Status mirrors the {"state", "detail"} status dicts.
type Status = monitor.Status

// BaseCollector implements the collector lifecycle: status, enable flag,
// start/stop with a background goroutine, sleep and event emission.
type BaseCollector struct {
	Ctx *monitor.Ctx

	name        string
	description string
	category    string

	mu      sync.Mutex
	status  Status
	enabled bool

	stopCh     chan struct{}
	stopClosed bool
	done       chan struct{}
	running    bool
	runFn      func()

	procsMu sync.Mutex
	procs   []*exec.Cmd
}

// NewBase initialises the common collector state (status "init", enabled).
func NewBase(ctx *monitor.Ctx, name, description, category string) *BaseCollector {
	return &BaseCollector{
		Ctx:         ctx,
		name:        name,
		description: description,
		category:    category,
		status:      Status{State: "init", Detail: ""},
		enabled:     true,
	}
}

// setRun installs the concrete collector's run loop (called by constructors).
func (b *BaseCollector) setRun(fn func()) { b.runFn = fn }

// Name returns the collector name (base class attribute `name`).
func (b *BaseCollector) Name() string { return b.name }

// Description returns the human-readable description.
func (b *BaseCollector) Description() string { return b.description }

// Category returns the monitoring category.
func (b *BaseCollector) Category() string { return b.category }

// Status returns the current status snapshot.
func (b *BaseCollector) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status
}

// SetStatus updates the status dict.
func (b *BaseCollector) SetStatus(state, detail string) {
	b.mu.Lock()
	b.status = Status{State: state, Detail: detail}
	b.mu.Unlock()
}

// Enabled reports whether the category toggle allows collection.
func (b *BaseCollector) Enabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enabled
}

// SetEnabled flips the category toggle.
func (b *BaseCollector) SetEnabled(enabled bool) {
	b.mu.Lock()
	b.enabled = enabled
	b.mu.Unlock()
}

// Available mirrors base.Collector.available; default: available.
func (b *BaseCollector) Available() (bool, string) { return true, "" }

// Run is the collector loop; concrete collectors override it.
func (b *BaseCollector) Run() {}

// Start launches the run loop in a background goroutine (once).
func (b *BaseCollector) Start() {
	b.mu.Lock()
	if b.running {
		b.mu.Unlock()
		return
	}
	b.stopCh = make(chan struct{})
	b.stopClosed = false
	b.done = make(chan struct{})
	b.running = true
	done := b.done
	b.mu.Unlock()
	go func() {
		// A run loop that exits on its own (dead stream, finished scan)
		// must clear running, or every later Start() early-returns and a
		// dashboard re-enable paints "active" over a dead collector.
		// LIFO: this runs before close(done), so Stop() never observes a
		// closed done with running still set.
		defer func() {
			b.mu.Lock()
			b.running = false
			b.mu.Unlock()
		}()
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				b.SetStatus("error", fmt.Sprintf("%v", r))
			}
		}()
		if b.runFn != nil {
			b.runFn()
		} else {
			b.Run()
		}
	}()
}

// Stop signals the run loop to exit, kills any subprocess it spawned and
// waits up to 3 seconds (mirrors base.stop with thread.join(timeout=3)).
// When the goroutine has exited, running is cleared so a later Start()
// (dashboard re-enable) relaunches it.
func (b *BaseCollector) Stop() {
	b.mu.Lock()
	ch, done := b.stopCh, b.done
	if ch != nil && !b.stopClosed {
		close(ch)
		b.stopClosed = true
	}
	b.mu.Unlock()
	b.killProcs()
	if done != nil {
		select {
		case <-done:
			b.mu.Lock()
			b.running = false
			b.mu.Unlock()
		case <-time.After(3 * time.Second):
			// stuck run loop: keep running set so a second Start() cannot
			// spawn a duplicate goroutine next to the stuck one
		}
	}
}

// Stopped reports whether the collector was asked to stop.
func (b *BaseCollector) Stopped() bool {
	b.mu.Lock()
	ch := b.stopCh
	b.mu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// Sleep waits for the given seconds, returning early on stop
// (mirrors base.sleep via threading.Event.wait).
func (b *BaseCollector) Sleep(seconds float64) {
	b.mu.Lock()
	ch := b.stopCh
	b.mu.Unlock()
	if ch == nil {
		time.Sleep(time.Duration(seconds * float64(time.Second)))
		return
	}
	select {
	case <-ch:
	case <-time.After(time.Duration(seconds * float64(time.Second))):
	}
}

// Emit publishes an event on the bus, applying the base-class defaults
// (category "system", kind "unknown").
func (b *BaseCollector) Emit(ev *monitor.Event) {
	if ev.Category == "" {
		ev.Category = "system"
	}
	if ev.Kind == "" {
		ev.Kind = "unknown"
	}
	b.Ctx.Bus.Publish(ev)
}

// registerProc tracks a long-running subprocess so Stop can kill it.
func (b *BaseCollector) registerProc(cmd *exec.Cmd) {
	b.procsMu.Lock()
	b.procs = append(b.procs, cmd)
	b.procsMu.Unlock()
}

func (b *BaseCollector) killProcs() {
	b.procsMu.Lock()
	procs := b.procs
	b.procs = nil
	b.procsMu.Unlock()
	for _, p := range procs {
		if p.Process != nil {
			// TERM first: a wrapper like `sudo fs_usage` relays the signal
			// to its privileged child and both exit -- a SIGKILL'd sudo
			// cannot relay, leaving the root child orphaned (a lone root
			// fs_usage blocks every future trace and the monitor cannot
			// kill it). KILL is only the escalation after a grace period.
			_ = monitor.KillCmdGroup(p.Process, syscall.SIGTERM)
			time.Sleep(300 * time.Millisecond)
			_ = monitor.KillCmdGroup(p.Process, syscall.SIGKILL)
			// Kill without Wait leaves a zombie until the process object is
			// finalized — reap immediately so nothing lingers for Sentinel
			// to flag. Wait returns at once for already-dead children.
			_ = p.Wait()
		}
	}
}
