package observability

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func loadBrakeFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "brake-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestContractNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Contract {
		if m.Name == "" {
			t.Fatal("contract has an unnamed metric")
		}
		if seen[m.Name] {
			t.Fatalf("duplicate metric name %q", m.Name)
		}
		seen[m.Name] = true
		if m.Computability == NeedsNewField && m.Gap == "" {
			t.Fatalf("metric %q needs a field but names no gap", m.Name)
		}
	}
}

func TestComputeFixture(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Compute(events)
	if rep.DeniedTotal != 3 {
		t.Fatalf("denied=%d want 3", rep.DeniedTotal)
	}
	wantRules := map[string]int64{"block_sensitive_egress": 1, "allow_destination": 1, "unattributed": 1}
	if !reflect.DeepEqual(rep.DeniedByRule, wantRules) {
		t.Fatalf("by_rule=%v want %v", rep.DeniedByRule, wantRules)
	}
	if rep.ApprovalGates != 1 {
		t.Fatalf("gates=%d want 1", rep.ApprovalGates)
	}
	if rep.ApprovalGrants != 1 {
		t.Fatalf("grants=%d want 1 (capability-accounted allow must not count)", rep.ApprovalGrants)
	}
	if rep.ChainIntercepts != 1 {
		t.Fatalf("chains=%d want 1", rep.ChainIntercepts)
	}
	if rep.TaintBlocks != 1 {
		t.Fatalf("taint_blocks=%d want 1", rep.TaintBlocks)
	}
}

func TestReconcileClean(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-deny-1", Decision: "deny"},
		{RequestHash: "req-deny-2", Decision: "deny"},
		{RequestHash: "req-allow-1", Decision: "allow"},
		{RequestHash: "", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 0 {
		t.Fatalf("unlogged=%d (%v) want 0", rep.UnloggedDenials, rep.UnloggedDetail)
	}
	if rep.Unjoinable != 1 {
		t.Fatalf("unjoinable=%d want 1 (hashless runtime-limits deny)", rep.Unjoinable)
	}
}

// TestReconcileCatchesMissingEvent is the negative case: a deny happened
// (declared) but no event was emitted. The gap must be caught, not silent.
func TestReconcileCatchesMissingEvent(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-deny-1", Decision: "deny"},
		{RequestHash: "req-vanished-9", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 1 {
		t.Fatalf("unlogged=%d want 1", rep.UnloggedDenials)
	}
	if len(rep.UnloggedDetail) != 1 || !strings.Contains(rep.UnloggedDetail[0], "req-vanished-9") {
		t.Fatalf("detail names the gap: %v", rep.UnloggedDetail)
	}
}

// TestHoldDoesNotSatisfyDenial: the approval hold shares req-hold-1 with the
// granted call, but no tool_call_denied carries it. Holds must never satisfy
// a denial lookup.
func TestHoldDoesNotSatisfyDenial(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-hold-1", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 1 {
		t.Fatalf("unlogged=%d want 1 (hold must not satisfy denial)", rep.UnloggedDenials)
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	if _, err := LoadEvents(bytes.NewReader([]byte("{oops\n"))); err == nil {
		t.Fatal("malformed line accepted")
	}
	if _, err := LoadEvents(bytes.NewReader([]byte("{\"timestamp\":\"x\"}\n"))); err == nil {
		t.Fatal("event without type accepted")
	}
}

func TestLoadLargeLine(t *testing.T) {
	// Production records can exceed 1 MiB (argument limit + envelope):
	// parsing must not cap line length.
	big := `{"timestamp":"2026-09-11T08:00:00Z","event_type":"session_started","session_id":"` + strings.Repeat("s", 2*1024*1024) + `","agent_id":"a","policy_decision":"allow"}` + "\n"
	events, err := LoadEvents(bytes.NewReader([]byte(big)))
	if err != nil {
		t.Fatalf("large line rejected: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
}

func TestReconcileConsumesMultiplicity(t *testing.T) {
	// Two declared denials, one logged occurrence (replay): the second is unlogged.
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-deny-1", Decision: "deny"},
		{RequestHash: "req-deny-1", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 1 {
		t.Fatalf("unlogged=%d want 1 (replay multiplicity)", rep.UnloggedDenials)
	}
}

func TestTruncatedTailRejected(t *testing.T) {
	data := loadBrakeFixture(t)
	// Strip the final newline: last record is now a torn tail.
	torn := bytes.TrimRight(data, "\n")
	if bytes.Equal(torn, data) {
		t.Skip("fixture has no trailing newline; rewrite surgery")
	}
	if _, err := LoadEvents(bytes.NewReader(torn)); err == nil {
		t.Fatal("torn tail accepted")
	}
	if _, err := LoadEvents(bytes.NewReader(data)); err != nil {
		t.Fatalf("clean fixture rejected: %v", err)
	}
}

func TestTrailingBlankSpaceAccepted(t *testing.T) {
	data := loadBrakeFixture(t)
	padded := append(append([]byte{}, data...), []byte("\n  \n")...)
	events, err := LoadEvents(bytes.NewReader(padded))
	if err != nil {
		t.Fatalf("trailing blank space rejected: %v", err)
	}
	if len(events) != 12 {
		t.Fatalf("events=%d want 12", len(events))
	}
}

func TestEmptyInputAccepted(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader([]byte("  \n")))
	if err != nil {
		t.Fatalf("blank input rejected: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events=%d want 0", len(events))
	}
}
