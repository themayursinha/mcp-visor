package capability

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// Codex P1 regression tests (PR #76): a STRUCTURED destination
// (Step.DestHost valid hostname OR Step.DestIP valid netip.Addr) is
// authoritative proof of an egress request, independent of the args surface.
// The proxy populates DestHost/DestIP for recognized network tools (and
// explicit dest_host/dest_ip on any tool). web_fetch/browse/fetch_url
// carrying a url/host arg must emit boundary.request_egress and Eval must
// PAUSE (E5), never ALLOW.
//
// This is ORTHOGONAL to the Rev 15 command-bearing-key discipline: the args
// surface is never scanned on non-command keys; a STRUCTURED destination is
// the proxy's authoritative observation of an egress request.

// Positive: every non-canonical net tool with a populated structured DestHost
// emits boundary.request_egress and Eval PAUSES (never ALLOW).
func TestP1StructuredDestHostEmitsEgressAndPauses(t *testing.T) {
	ws := t.TempDir()
	for _, tool := range []string{"web_fetch", "browse", "fetch_url"} {
		t.Run(tool, func(t *testing.T) {
			e, err := NewChainEvaluator("sess-p1-host-" + tool)
			if err != nil {
				t.Fatal(err)
			}
			r, err := e.Eval(context.Background(), Step{
				SessionID: "sess-p1-host-" + tool,
				StepID:    1,
				Tool:      tool,
				Args:      map[string]string{"url": "https://example.com"},
				DestHost:  "example.com",
				Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
			}, GenesisPrevHash)
			if err != nil {
				t.Fatalf("Eval failed: %v", err)
			}
			if r.Decision != DecisionPauseRequireProof {
				t.Fatalf("%s with structured DestHost must PAUSE (E5), got %s", tool, r.Decision)
			}
			if !hasSignal(r.Signals, SignalBoundaryEgress) {
				t.Fatalf("%s receipt must carry boundary.request_egress, got %+v", tool, r.Signals)
			}
		})
	}
}

// Positive: a populated structured DestIP is also an egress request, even for
// an arbitrary tool name.
func TestP1StructuredDestIPIsEgressAndPauses(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-p1-ip")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-p1-ip",
		StepID:    1,
		Tool:      "custom_net_tool",
		DestIP:    netip.MustParseAddr("203.0.113.9"),
		Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatalf("Eval failed: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof {
		t.Fatalf("populated DestIP must PAUSE (E5), got %s", r.Decision)
	}
	if !hasSignal(r.Signals, SignalBoundaryEgress) {
		t.Fatalf("populated DestIP receipt must carry boundary.request_egress, got %+v", r.Signals)
	}
}

// Negative: a malformed populated DestHost must FAIL CLOSED (evaluator error
// → PAUSE), never ALLOW and never an ordinary E5.
func TestP1MalformedDestHostFailsClosed(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-p1-malformed")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Eval(context.Background(), Step{
		SessionID: "sess-p1-malformed",
		StepID:    1,
		Tool:      "web_fetch",
		Args:      map[string]string{"url": "https://bad host!"},
		DestHost:  "bad host!",
		Declared:  DeclaredAuthority{Target: "target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err == nil {
		t.Fatal("malformed DestHost must be evaluator error (fail closed), got nil")
	}
	if !errors.Is(err, ErrInvalidStep) {
		t.Fatalf("malformed DestHost error must wrap ErrInvalidStep, got %v", err)
	}
}

// Negative: benign payload in a non-command key stays protected. A
// write_file({"content":"curl https://x"}) with NO structured destination must
// NOT emit egress (Rev 15 discipline preserved — no args scanning on
// non-command keys).
func TestP1BenignPayloadNonCommandKeyStillProtected(t *testing.T) {
	sigs := ExtractSignals(Step{
		Tool: "write_file",
		Args: map[string]string{"content": "curl https://evil.example/x"},
	})
	if hasSignal(sigs, SignalBoundaryEgress) {
		t.Fatalf("write_file content must not emit egress (benign payload), got %+v", sigs)
	}
}

// Unit control: egressFromArgs must report true when a STRUCTURED destination
// is populated (even on a tool name that is not a canonical net tool), and
// must still be false for a benign payload without a structured destination.
func TestP1EgressFromArgsStructuredDestinationUnit(t *testing.T) {
	if !egressFromArgs(Step{Tool: "web_fetch", DestHost: "example.com"}, "") {
		t.Fatal("egressFromArgs must report true for a populated structured DestHost")
	}
	if !egressFromArgs(Step{Tool: "custom", DestIP: netip.MustParseAddr("10.0.0.7")}, "") {
		t.Fatal("egressFromArgs must report true for a populated structured DestIP")
	}
	if egressFromArgs(Step{Tool: "write_file", Args: map[string]string{"content": "curl https://x"}}, "") {
		t.Fatal("egressFromArgs must not report egress for benign payload without a structured destination")
	}
}
