package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func trajectoryPolicy() string {
	return `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "alpha"
        allowed: true
      - name: "bravo"
        allowed: true
      - name: "charlie"
        allowed: true
      - name: "delta"
        allowed: true
      - name: "echo"
        allowed: false
      - name: "foxtrot"
        allowed: true
      - name: "spawn_agent"
        allowed: true
      - name: "needs_ok"
        allowed: true
        approval_required: true
tool_chains:
  - name: "later-deny"
    sources:
      - server: "*"
        tool_pattern: "alpha"
    sinks:
      - server: "*"
        tool_pattern: "spawn_agent"
    action: deny
    within_calls: 32
`
}

func newTrajectoryProxy(t *testing.T, enabled bool, approvalDir string) (*Proxy, string, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	cfg := Config{
		ServerName:        "workspace",
		SessionID:         "sess-" + t.Name(),
		ClientID:          "agent-traj",
		AuditLogPath:      auditPath,
		ApprovalDir:       approvalDir,
		TrajectoryAdvisor: enabled,
		Policy:            mustLoadPolicy(t, trajectoryPolicy()),
	}
	p := New(cfg)
	t.Cleanup(func() { p.audit.Close() })
	return p, auditPath, &bytes.Buffer{}
}

func trajCall(p *Proxy, out *bytes.Buffer, id int, tool string) (json.RawMessage, string, string) {
	out.Reset()
	client := mcp.NewParser(nil, out)
	raw, action := p.interceptAndModify(toolCallRaw(id, tool, map[string]any{"n": id}), client)
	if action == "forward" {
		p.session.RecordToolCall(p.cfg.ServerName, mcp.ToolsCallRequest{Name: tool}, "")
	}
	return raw, action, out.String()
}

func warmupTrajectory(t *testing.T, p *Proxy, out *bytes.Buffer) {
	t.Helper()
	tools := []string{"alpha", "bravo", "alpha", "bravo", "charlie", "delta", "charlie", "delta", "charlie"}
	for i, name := range tools {
		_, action, resp := trajCall(p, out, i+1, name)
		if action != "forward" {
			t.Fatalf("warmup %s: action=%s resp=%s", name, action, resp)
		}
	}
}

func assertAdvice(t *testing.T, ev audit.Event) {
	t.Helper()
	if ev.TrajectoryAdvice == nil {
		t.Fatalf("missing trajectory_advice on %+v", ev)
	}
	a := ev.TrajectoryAdvice
	if a.Advisor != "session_unseen_bigram_v1" || a.Kind != "unseen_successor" {
		t.Fatalf("advice identity: %+v", a)
	}
	if a.WindowTransitions != 8 || a.SourceSupport != 2 || a.TransitionSupport != 0 {
		t.Fatalf("advice counts: %+v", a)
	}
	if len(a.Sequence) != 2 || a.Sequence[0] != "workspace:charlie" {
		t.Fatalf("sequence: %v", a.Sequence)
	}
}

func countJSONL(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func TestTrajectoryAdvisorDefaultOff(t *testing.T) {
	p, auditPath, out := newTrajectoryProxy(t, false, "")
	if p.trajectoryAdvisor != nil {
		t.Fatal("default-off must not construct advisor")
	}
	warmupTrajectory(t, p, out)
	_, action, _ := trajCall(p, out, 10, "delta")
	if action != "forward" {
		t.Fatalf("allow: %s", action)
	}
	_, action, resp := trajCall(p, out, 11, "echo")
	if action != "denied" {
		t.Fatalf("deny: %s %s", action, resp)
	}
	if p.metrics.TrajectoryAnomalies != 0 {
		t.Fatalf("metric=%d", p.metrics.TrajectoryAnomalies)
	}
	for _, ev := range []audit.Event{
		findAuditEvent(t, auditPath, audit.EventToolAllowed, "delta"),
		findAuditEvent(t, auditPath, audit.EventToolDenied, "echo"),
	} {
		if ev.TrajectoryAdvice != nil {
			t.Fatalf("unexpected advice: %+v", ev.TrajectoryAdvice)
		}
	}
}

func TestTrajectoryAdvisorEnabledUnseenSuccessor(t *testing.T) {
	p, auditPath, out := newTrajectoryProxy(t, true, "")
	if p.trajectoryAdvisor == nil {
		t.Fatal("enabled must construct advisor")
	}
	warmupTrajectory(t, p, out)
	_, action, _ := trajCall(p, out, 10, "foxtrot")
	if action != "forward" {
		t.Fatalf("unseen allow: %s", action)
	}
	if p.metrics.TrajectoryAnomalies != 1 {
		t.Fatalf("metric=%d", p.metrics.TrajectoryAnomalies)
	}
	ev := lastAuditEvent(t, auditPath, audit.EventToolAllowed, "foxtrot")
	assertAdvice(t, ev)
	if ev.TrajectoryAdvice.Sequence[1] != "workspace:foxtrot" {
		t.Fatalf("seq %v", ev.TrajectoryAdvice.Sequence)
	}
}

func TestTrajectoryAdvisorKnownTransition(t *testing.T) {
	p, auditPath, out := newTrajectoryProxy(t, true, "")
	warmupTrajectory(t, p, out)
	_, action, _ := trajCall(p, out, 10, "delta")
	if action != "forward" || p.metrics.TrajectoryAnomalies != 0 {
		t.Fatalf("action=%s metric=%d", action, p.metrics.TrajectoryAnomalies)
	}
	if findAuditEvent(t, auditPath, audit.EventToolAllowed, "delta").TrajectoryAdvice != nil {
		t.Fatal("warmup delta must omit advice")
	}
	if lastAuditEvent(t, auditPath, audit.EventToolAllowed, "delta").TrajectoryAdvice != nil {
		t.Fatal("nested advice on known transition")
	}
}

func TestTrajectoryAdvisorPolicyDeniedRemainsDenied(t *testing.T) {
	p, auditPath, out := newTrajectoryProxy(t, true, "")
	warmupTrajectory(t, p, out)
	raw, action, resp := trajCall(p, out, 10, "echo")
	if action != "denied" || strings.Contains(resp, `"result"`) {
		t.Fatalf("must deny without relay: %s %s", action, resp)
	}
	if p.metrics.TrajectoryAnomalies != 1 {
		t.Fatalf("metric=%d", p.metrics.TrajectoryAnomalies)
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "echo")
	assertAdvice(t, ev)
	_ = raw
}

func TestTrajectoryAdvisorAnomalousAllowRemainsForward(t *testing.T) {
	p, _, out := newTrajectoryProxy(t, true, "")
	warmupTrajectory(t, p, out)
	_, action, _ := trajCall(p, out, 10, "foxtrot")
	if action != "forward" {
		t.Fatalf("must remain forward, got %s", action)
	}
	if p.metrics.TrajectoryAnomalies != 1 {
		t.Fatalf("metric=%d", p.metrics.TrajectoryAnomalies)
	}
}

func TestTrajectoryAdvisorApprovalNotAutoApproved(t *testing.T) {
	approvalDir := t.TempDir()
	p, auditPath, out := newTrajectoryProxy(t, true, approvalDir)
	warmupTrajectory(t, p, out)
	done := make(chan string, 1)
	go func() {
		_, action, _ := trajCall(p, out, 10, "needs_ok")
		done <- action
	}()
	var matches []string
	for i := 0; i < 2_000_000; i++ {
		matches, _ = filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
		if len(matches) > 0 {
			break
		}
		select {
		case act := <-done:
			t.Fatalf("finished before approval file: %s", act)
		default:
			runtime.Gosched()
		}
	}
	if len(matches) == 0 {
		t.Fatal("never entered existing approval path")
	}
	select {
	case act := <-done:
		t.Fatalf("auto-approved: %s", act)
	default:
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolApprovalRequired, "needs_ok")
	assertAdvice(t, ev)
	if p.metrics.TrajectoryAnomalies != 1 {
		t.Fatalf("metric=%d", p.metrics.TrajectoryAnomalies)
	}
	id := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if act := <-done; act != "forward" {
		t.Fatalf("operator approve: %s", act)
	}
}

func TestTrajectoryAdvisorLaterDenyRemainsDenied(t *testing.T) {
	p, auditPath, out := newTrajectoryProxy(t, true, "")
	warmupTrajectory(t, p, out)
	_, action, resp := trajCall(p, out, 10, "spawn_agent")
	if action != "denied" {
		t.Fatalf("later chain deny must remain deny, got %s %s", action, resp)
	}
	if p.metrics.TrajectoryAnomalies != 1 {
		t.Fatalf("metric=%d", p.metrics.TrajectoryAnomalies)
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolDenied, "spawn_agent")
	assertAdvice(t, ev)
}

func TestTrajectoryAdvisorNoExtraAuditLine(t *testing.T) {
	p, auditPath, out := newTrajectoryProxy(t, true, "")
	warmupTrajectory(t, p, out)
	before := countJSONL(t, auditPath)
	_, action, _ := trajCall(p, out, 10, "foxtrot")
	if action != "forward" {
		t.Fatalf("action=%s", action)
	}
	if got := countJSONL(t, auditPath); got != before+1 {
		t.Fatalf("lines before=%d after=%d (advisor must not emit a second line)", before, got)
	}
}

func TestTrajectoryAdvisorPerProxyState(t *testing.T) {
	p1, _, out1 := newTrajectoryProxy(t, true, "")
	p2, audit2, out2 := newTrajectoryProxy(t, true, "")
	warmupTrajectory(t, p1, out1)
	_, action, _ := trajCall(p1, out1, 10, "bravo")
	if action != "forward" || p1.metrics.TrajectoryAnomalies != 1 {
		t.Fatalf("p1 action=%s metric=%d", action, p1.metrics.TrajectoryAnomalies)
	}
	_, action, _ = trajCall(p2, out2, 1, "bravo")
	if action != "forward" || p2.metrics.TrajectoryAnomalies != 0 {
		t.Fatalf("p2 must not inherit support, action=%s metric=%d", action, p2.metrics.TrajectoryAnomalies)
	}
	if findAuditEvent(t, audit2, audit.EventToolAllowed, "bravo").TrajectoryAdvice != nil {
		t.Fatal("p2 first call must omit advice")
	}
}

func TestTrajectoryAdvisorEnabledDisabledParity(t *testing.T) {
	// stdio interceptAndModify and remote intercept share processToolsCall; no separate advisor wiring.
	off, _, outOff := newTrajectoryProxy(t, false, "")
	on, _, outOn := newTrajectoryProxy(t, true, "")
	warmupTrajectory(t, off, outOff)
	warmupTrajectory(t, on, outOn)
	offRaw, offAct, offResp := trajCall(off, outOff, 10, "bravo")
	onRaw, onAct, onResp := trajCall(on, outOn, 10, "bravo")
	if offAct != onAct || offResp != onResp || !bytes.Equal(offRaw, onRaw) {
		t.Fatalf("allow parity off=%s %q on=%s %q", offAct, offResp, onAct, onResp)
	}
	offRaw, offAct, offResp = trajCall(off, outOff, 11, "echo")
	onRaw, onAct, onResp = trajCall(on, outOn, 11, "echo")
	if offAct != "denied" || offAct != onAct || offResp != onResp || !bytes.Equal(offRaw, onRaw) {
		t.Fatalf("deny parity off=%s %q on=%s %q", offAct, offResp, onAct, onResp)
	}
	if on.metrics.TrajectoryAnomalies == 0 || off.metrics.TrajectoryAnomalies != 0 {
		t.Fatalf("metrics off=%d on=%d", off.metrics.TrajectoryAnomalies, on.metrics.TrajectoryAnomalies)
	}
}
