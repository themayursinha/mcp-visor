package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/themayursinha/mcp-visor/internal/demoutil"
)

// Snapshot is a read-only projection of the demo audit JSONL and observe-log.
// It must not invent allow/deny decisions.
type Snapshot struct {
	AuditEvents  []map[string]any   `json:"audit_events"`
	Observations []demoutil.ObsLine `json:"observations"`
	Integrity    string             `json:"integrity,omitempty"`
}

func snapshotHasDeny(s Snapshot) bool {
	for _, ev := range s.AuditEvents {
		if decision, _ := ev["policy_decision"].(string); decision == "deny" {
			return true
		}
		if et, _ := ev["event_type"].(string); et == "tool_call_denied" {
			return true
		}
	}
	return false
}

func httpPost300Received(s Snapshot) bool {
	for _, o := range s.Observations {
		if o.Tool == "http_post" && o.RequestID == 300 && o.Received {
			return true
		}
	}
	return false
}

func nonRelayProven(s Snapshot) bool {
	return demoutil.ValidateObservations(s.Observations) == nil
}

func validateListenAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("listen address %q missing port", addr)
	}
	if host == "" {
		return errors.New("proof console must bind loopback or Tailscale (empty host binds all interfaces)")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("proof console must bind loopback or Tailscale, got %q", host)
	}
	if ip.IsLoopback() || isTailscaleIP(ip) {
		return nil
	}
	return fmt.Errorf("proof console must bind loopback or Tailscale, got %q", host)
}

// isTailscaleIP reports whether ip is in Tailscale's CGNAT range (100.64.0.0/10).
// LAN, Wi-Fi, and wildcard binds remain rejected.
func isTailscaleIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

func readSnapshot(auditPath, observePath string) (Snapshot, error) {
	events, err := readAuditEvents(auditPath)
	if err != nil {
		return Snapshot{}, err
	}
	obs, err := readObservationsFile(observePath)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{AuditEvents: events, Observations: obs}, nil
}

func proofIntegrity(s Snapshot) string {
	if err := demoutil.ValidateObservations(s.Observations); err != nil {
		return err.Error()
	}
	if err := demoutil.ValidateEvidence(evidenceFromEvents(s.AuditEvents)); err != nil {
		return err.Error()
	}
	return "ok"
}

func evidenceFromEvents(events []map[string]any) *demoutil.DemoEvidence {
	ev := &demoutil.DemoEvidence{}
	for _, event := range events {
		switch event["event_type"] {
		case "session_tainted":
			ev.Taint = extractTaintName(event)
			ev.SourceTool, _ = event["tool"].(string)
		case "tool_call_denied":
			ev.SinkTool, _ = event["tool"].(string)
			ev.Rule, _ = event["policy_rule"].(string)
			ev.Decision, _ = event["policy_decision"].(string)
		}
	}
	return ev
}

func readAuditEvents(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		out = append(out, event)
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func readObservationsFile(path string) ([]demoutil.ObsLine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []demoutil.ObsLine{}, nil
		}
		return nil, fmt.Errorf("read observe-log: %w", err)
	}
	var out []demoutil.ObsLine
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		tool, _ := m["tool"].(string)
		received, _ := m["received"].(bool)
		var reqID int
		if v, ok := m["request_id"].(float64); ok {
			reqID = int(v)
		}
		out = append(out, demoutil.ObsLine{Tool: tool, RequestID: reqID, Received: received})
	}
	if out == nil {
		out = []demoutil.ObsLine{}
	}
	return out, nil
}
