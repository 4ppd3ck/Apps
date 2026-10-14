package main

// Alert delivery: SSE hub for the dashboard + OS desktop notifications.
// Every OS path is a best-effort exec of the platform's native notifier.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Hub fans out JSON payloads to SSE subscribers.
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 32)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *Hub) Broadcast(payload any) {
	raw, err := jsonMarshal(payload)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- raw:
		default: // slow client: drop rather than block the engine
		}
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// NotifyWebhook posts an alert out-of-band. Formats:
//
//	json     — POST {"severity","title","detail","check","ts"} (generic)
//	ntfy     — POST body as plain text, Title header (ntfy.sh self-host ok)
//	telegram — bot API sendMessage to chat id (needs webhook_chat_id)
//
// Fire-and-forget with a short timeout; failure never blocks the engine.
func NotifyWebhook(a *Alert, rules *Notify) {
	if rules == nil || rules.WebhookURL == "" {
		return
	}
	if !SevGE(a.Severity, orDefault(rules.MinSeverity, SevMedium)) {
		return
	}
	format := rules.WebhookFormat
	if format == "" {
		format = "json"
	}
	var body io.Reader
	url := rules.WebhookURL
	ct := "application/json"
	switch strings.ToLower(format) {
	case "ntfy":
		body = strings.NewReader(fmt.Sprintf("%s\n%s", a.Title, a.Detail))
		// headers via a custom request below
	case "telegram":
		url = strings.TrimRight(rules.WebhookURL, "/") +
			"?chat_id=" + urlQueryEscape(rules.WebhookChatID)
		payload, _ := jsonMarshal(map[string]string{
			"chat_id": rules.WebhookChatID,
			"text": fmt.Sprintf("🚨 Sentinel %s: %s — %s",
				strings.ToUpper(a.Severity), a.Title, a.Detail),
		})
		body = bytes.NewReader(payload)
	default: // json
		payload, _ := jsonMarshal(map[string]any{
			"severity": a.Severity, "title": a.Title, "detail": a.Detail,
			"check": a.Check, "ts": a.Ts, "count": a.Count,
		})
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", ct)
	if strings.EqualFold(format, "ntfy") {
		req.Header.Set("Title", "Sentinel "+strings.ToUpper(a.Severity)+": "+a.Title)
		req.Header.Set("Priority", sevPriority(a.Severity))
		req.Header.Set("Tags", "rotating_light")
	}
	go func() {
		client := &http.Client{Timeout: 6 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func sevPriority(sev string) string {
	switch sev {
	case SevCritical, SevHigh:
		return "high"
	case SevMedium:
		return "default"
	default:
		return "low"
	}
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// Notify sends a desktop notification for an alert. Best effort everywhere.
func NotifyAlert(a *Alert, sound bool) {
	title := fmt.Sprintf("🚨 Sentinel: %s", strings.ToUpper(a.Severity))
	body := fmt.Sprintf("%s — %s", a.Title, a.Detail)
	if len(body) > 180 {
		body = body[:180] + "…"
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf("display notification %q with title %q",
			shellQuoteApple(body), shellQuoteApple(title))
		if sound {
			script += " sound name \"Soso\""
		}
		cmd = exec.Command("osascript", "-e", script)
	case "linux":
		cmd = exec.Command("notify-send", "-a", "Sentinel", title, body)
	case "windows":
		// Detached PowerShell message box; never blocks the engine.
		ps := fmt.Sprintf(
			`Add-Type -AssemblyName PresentationFramework; `+
				`[System.Windows.MessageBox]::Show('%s','%s')`,
			psQuote(body), psQuote(title))
		cmd = exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	case "freebsd", "openbsd", "netbsd":
		cmd = exec.Command("notify-send", "-a", "Sentinel", title, body)
	default:
		return
	}
	if cmd == nil {
		return
	}
	go func() {
		_ = cmd.Run() // best effort; a missing notifier just fails silently
	}()
}

func shellQuoteApple(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

func psQuote(s string) string {
	return strings.NewReplacer("'", "''").Replace(s)
}
