package audit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func kineticEvent() Event {
	return Event{
		EventType:               EventKineticStopEnforced,
		SessionID:               "sess-k",
		AgentID:                 "agent-k",
		Server:                  "helper",
		Decision:                "revoked",
		Reason:                  "halt",
		ControllerID:            "c1",
		CommandID:               "aabbccddaabbccddaabbccddaabbccdd",
		SessionEpoch:            2,
		RevokedThroughEpoch:     2,
		ObservedEnforcementTime: "2026-01-01T00:00:00.000000001Z",
		ResultingState:          "revoked_contained",
		ControlRequestSHA256:    "ab" + "cd" + "ef" + "01" + "23" + "45" + "67" + "89" + "ab" + "cd" + "ef" + "01" + "23" + "45" + "67" + "89" + "ab" + "cd" + "ef" + "01" + "23" + "45" + "67" + "89" + "ab" + "cd" + "ef" + "01" + "23" + "45" + "67" + "89",
	}
}

func TestCommitKineticStopWritesSyncsThenAdvances(t *testing.T) {
	l, err := NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var order []string
	var syncIdx uint64
	l.writeFn = func(b []byte) (int, error) { order = append(order, "write"); return len(b), nil }
	l.syncFn = func() error { order = append(order, "sync"); syncIdx = l.chainIndex; return nil }
	before := l.chainIndex
	if err := l.CommitKineticStop(kineticEvent()); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "write" || order[1] != "sync" || syncIdx != before || l.chainIndex != before+1 {
		t.Fatalf("%v idx=%d", order, l.chainIndex)
	}
}

func TestCommitKineticStopRejectsWrongEventOrDecision(t *testing.T) {
	l, err := NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ev := kineticEvent()
	ev.EventType = EventToolDenied
	if err := l.CommitKineticStop(ev); err == nil {
		t.Fatal("type")
	}
	ev = kineticEvent()
	ev.Decision = "deny"
	if err := l.CommitKineticStop(ev); err == nil {
		t.Fatal("decision")
	}
	ev = kineticEvent()
	ev.ResultingState = ""
	if err := l.CommitKineticStop(ev); err == nil {
		t.Fatal("state")
	}
}

func TestCommitKineticStopFailsOnNonDurableSink(t *testing.T) {
	l := stderrLogger()
	if err := l.CommitKineticStop(kineticEvent()); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("%v", err)
	}
	if !l.poisoned || l.Durable() {
		t.Fatal("poison")
	}
}

func TestKineticStopEventHashBindsControllerEpochTimeAndState(t *testing.T) {
	a := kineticEvent()
	ha, err := RecordHash(a)
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.ControllerID = "other"
	hb, _ := RecordHash(b)
	c := a
	c.SessionEpoch = 9
	hc, _ := RecordHash(c)
	d := a
	d.ObservedEnforcementTime = "2026-02-01T00:00:00Z"
	hd, _ := RecordHash(d)
	e := a
	e.ResultingState = "contained_control_invalid"
	he, _ := RecordHash(e)
	if ha == hb || ha == hc || ha == hd || ha == he {
		t.Fatal("hash collision")
	}
	_ = io.Discard
	_ = os.ErrClosed
}
