package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func ceilingPolicyYAML() string {
	return `
version: "1.0"
description: "Delegation ceiling lab"
default_action: deny
settings:
  max_spawn_depth: 2
servers:
  - name: "orchestrator"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "spawn_agent"
        allowed: true
        risk: high
        delegates: true
`
}

func newCeilingProxy(t *testing.T, session string) (*Proxy, *bytes.Buffer, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "orchestrator",
		SessionID:    session,
		ClientID:     "agent-parent",
		AuditLogPath: auditPath,
		Policy:       mustLoadPolicy(t, ceilingPolicyYAML()),
	})
	t.Cleanup(func() { p.audit.Close() })
	return p, out, auditPath
}

func spawnCall(p *Proxy, out *bytes.Buffer, id int, task string, client *mcp.Parser) (json.RawMessage, string) {
	return p.interceptAndModify(toolCallRaw(id, "spawn_agent", map[string]any{"task": task}), client)
}

func TestDelegationCeilingDeniesPastBudget(t *testing.T) {
	p, out, _ := newCeilingProxy(t, "sess-ceil")
	client := mcp.NewParser(nil, out)

	for _, id := range []int{1, 2} {
		out.Reset()
		if _, action := spawnCall(p, out, id, "job", client); action != "forward" {
			t.Fatalf("spawn %d within budget must forward, got %s", id, action)
		}
		if got := p.session.DelegationDepth(); got != id {
			t.Fatalf("depth=%d want %d", got, id)
		}
	}

	out.Reset()
	_, action := spawnCall(p, out, 3, "job", client)
	if action != "denied" {
		t.Fatalf("spawn past ceiling must deny, got %s", action)
	}
	if !strings.Contains(out.String(), "delegation ceiling exceeded") {
		t.Fatalf("denial must name the ceiling, got %s", out.String())
	}
	for _, frag := range []string{"argument class DELEGATION", "effect class DELEGATION", "PARENT-", "CHILD"} {
		if !strings.Contains(out.String(), frag) {
			t.Fatalf("denial must carry %q, got %s", frag, out.String())
		}
	}
	if got := p.session.DelegationDepth(); got != 2 {
		t.Fatalf("denied spawn must not consume budget, depth=%d want 2", got)
	}
}

func TestDelegationCeilingAuditCarriesDepth(t *testing.T) {
	p, out, auditPath := newCeilingProxy(t, "sess-ceil-audit")
	client := mcp.NewParser(nil, out)

	for _, id := range []int{1, 2} {
		out.Reset()
		if _, action := spawnCall(p, out, id, "job", client); action != "forward" {
			t.Fatalf("spawn %d must forward, got %s", id, action)
		}
	}
	out.Reset()
	if _, action := spawnCall(p, out, 3, "job", client); action != "denied" {
		t.Fatalf("spawn 3 must deny, got %s", action)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.EventType == audit.EventToolDenied && ev.Tool == "spawn_agent" {
			found = true
			if ev.DelegationDepth != 2 || ev.MaxSpawnDepth != 2 {
				t.Fatalf("deny event depth=%d max=%d want 2/2", ev.DelegationDepth, ev.MaxSpawnDepth)
			}
		}
	}
	if !found {
		t.Fatal("no spawn_agent deny event in audit log")
	}
}

func TestDelegationCeilingIgnoresOtherTools(t *testing.T) {
	p, out, _ := newCeilingProxy(t, "sess-ceil-mixed")
	client := mcp.NewParser(nil, out)

	for i := 1; i <= 4; i++ {
		out.Reset()
		if _, action := p.interceptAndModify(toolCallRaw(10+i, "file_read", map[string]any{"path": "/workspace/t.md"}), client); action != "forward" {
			t.Fatalf("read %d must forward, got %s", i, action)
		}
	}
	if got := p.session.DelegationDepth(); got != 0 {
		t.Fatalf("reads must not consume budget, depth=%d", got)
	}
	out.Reset()
	if _, action := spawnCall(p, out, 20, "job", client); action != "forward" {
		t.Fatalf("first spawn must forward, got %s", action)
	}
}

func TestDelegationCeilingOffByDefault(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := &bytes.Buffer{}
	p := New(Config{
		ServerName:   "orchestrator",
		SessionID:    "sess-ceil-off",
		ClientID:     "agent-parent",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
servers:
  - name: "orchestrator"
    allowed: true
    tools:
      - name: "spawn_agent"
        allowed: true
        delegates: true
`),
	})
	defer p.audit.Close()
	client := mcp.NewParser(nil, out)

	for i := 1; i <= 5; i++ {
		out.Reset()
		if _, action := spawnCall(p, out, i, "job", client); action != "forward" {
			t.Fatalf("unenforced spawn %d must forward, got %s", i, action)
		}
	}
}

func TestDelegationCeilingConcurrentReserve(t *testing.T) {
	// Eight concurrent spawns against max 1: exactly one forwards, seven
	// deny. Proves check-and-reserve is atomic (separate read+increment
	// would over-admit past the hard cap).
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:   "orchestrator",
		SessionID:    "sess-ceil-race",
		ClientID:     "agent-parent",
		AuditLogPath: auditPath,
		Policy: mustLoadPolicy(t, `
version: "1.0"
default_action: deny
settings:
  max_spawn_depth: 1
servers:
  - name: "orchestrator"
    allowed: true
    tools:
      - name: "spawn_agent"
        allowed: true
        delegates: true
`),
	})
	defer p.audit.Close()

	const racers = 8
	results := make(chan string, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			out := &bytes.Buffer{}
			client := mcp.NewParser(nil, out)
			<-start
			_, action := p.interceptAndModify(toolCallRaw(100+id, "spawn_agent", map[string]any{"task": "job"}), client)
			results <- action
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	forwarded := 0
	for action := range results {
		if action == "forward" {
			forwarded++
		}
	}
	if forwarded != 1 {
		t.Fatalf("forwarded=%d want exactly 1 (atomic reserve)", forwarded)
	}
	if got := p.session.DelegationDepth(); got != 1 {
		t.Fatalf("depth=%d want 1", got)
	}
}

func TestSessionReserveRelease(t *testing.T) {
	s := NewSession("s", "c")
	if _, ok := s.TryReserveDelegation(1); !ok {
		t.Fatal("first reserve must succeed")
	}
	if _, ok := s.TryReserveDelegation(1); ok {
		t.Fatal("second reserve past max must fail")
	}
	s.ReleaseDelegation()
	if got := s.DelegationDepth(); got != 0 {
		t.Fatalf("depth=%d want 0 after release", got)
	}
	s.ReleaseDelegation()
	if got := s.DelegationDepth(); got != 0 {
		t.Fatalf("release must floor at zero, depth=%d", got)
	}
}
