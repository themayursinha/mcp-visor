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
	if err := validateCanonicalProof(s); err != nil {
		return err.Error()
	}
	return "ok"
}

func validateCanonicalProof(s Snapshot) error {
	if err := demoutil.ValidateObservations(s.Observations); err != nil {
		return err
	}

	var allows []map[string]any
	var taint, deny map[string]any
	for _, ev := range s.AuditEvents {
		switch ev["event_type"] {
		case "tool_call_allowed":
			if tool, _ := ev["tool"].(string); tool == "file_read" {
				allows = append(allows, ev)
			}
		case "session_tainted":
			taint = ev
		case "tool_call_denied":
			deny = ev
		}
	}
	if len(allows) < 2 {
		return errors.New("missing file_read allow events")
	}
	for _, a := range allows {
		if hash, _ := a["hash"].(string); hash == "" {
			return errors.New("allow missing hash")
		}
	}
	if taint == nil {
		return errors.New("missing session_tainted")
	}
	if tool, _ := taint["tool"].(string); tool != "file_read" {
		return errors.New("taint source is not file_read")
	}
	if !eventHasTaint(taint, "sensitive_file_accessed") {
		return errors.New("missing taint sensitive_file_accessed")
	}
	if deny == nil {
		return errors.New("missing tool_call_denied")
	}
	if tool, _ := deny["tool"].(string); tool != "http_post" {
		return errors.New("deny sink is not http_post")
	}
	if rule, _ := deny["policy_rule"].(string); rule != "block_sensitive_egress" {
		return errors.New("deny rule is not block_sensitive_egress")
	}
	if decision, _ := deny["policy_decision"].(string); decision != "deny" {
		return errors.New("deny decision is not deny")
	}
	if err := validateHashLinkage(s.AuditEvents); err != nil {
		return err
	}
	return nil
}

func eventHasTaint(ev map[string]any, name string) bool {
	if extractTaintName(ev) == name {
		return true
	}
	raw, ok := ev["session_taints"].([]any)
	if !ok {
		return false
	}
	for _, v := range raw {
		if s, ok := v.(string); ok && s == name {
			return true
		}
	}
	return false
}

func validateHashLinkage(events []map[string]any) error {
	type rec struct {
		idx  uint64
		hash string
		prev string
	}
	var rows []rec
	for _, ev := range events {
		hash, _ := ev["hash"].(string)
		if hash == "" {
			continue
		}
		rows = append(rows, rec{
			idx:  chainIndex(ev),
			hash: hash,
			prev: stringField(ev, "prev_hash"),
		})
	}
	if len(rows) < 2 {
		return errors.New("missing hash-linked audit events")
	}
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j].idx < rows[j-1].idx; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].prev != rows[i-1].hash {
			return errors.New("audit hash chain is broken")
		}
	}
	return nil
}

func stringField(ev map[string]any, key string) string {
	s, _ := ev[key].(string)
	return s
}

func chainIndex(ev map[string]any) uint64 {
	switch v := ev["chain_index"].(type) {
	case float64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	default:
		return 0
	}
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
