package audit

import (
	"errors"
	"io"
	"path/filepath"
	"testing"
)

// These tests use package-level or struct-level seams that must not run in
// parallel with other tests in the package.

func TestNewLoggerSyncsParentUnconditionally(t *testing.T) {
	old := syncParentDir
	calls := 0
	syncParentDir = func(string) error {
		calls++
		return nil
	}
	defer func() { syncParentDir = old }()

	newPath := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, label := range []string{"new ledger", "existing ledger"} {
		calls = 0
		l, err := NewLogger(newPath)
		if err != nil {
			t.Fatalf("NewLogger (%s): %v", label, err)
		}
		_ = l.Close()
		if calls != 1 {
			t.Fatalf("expected exactly 1 parent sync for %s, got %d", label, calls)
		}
	}
}

func newCommitLogger(t *testing.T) *Logger {
	t.Helper()
	l, err := NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func commitAllowEvent() Event {
	return Event{
		EventType: EventToolAllowed,
		SessionID: "sess-commit",
		AgentID:   "agent-commit",
		Server:    "filesystem",
		Tool:      "file_read",
		Decision:  "allow",
		Reason:    "allowed by policy",
	}
}

func TestCommitAuthorizationWritesThenSyncsBeforeAdvancing(t *testing.T) {
	l := newCommitLogger(t)

	var order []string
	var syncSeenChain uint64
	l.writeFn = func(b []byte) (int, error) {
		order = append(order, "write")
		return len(b), nil
	}
	l.syncFn = func() error {
		order = append(order, "sync")
		syncSeenChain = l.chainIndex
		return nil
	}

	before := l.chainIndex
	if err := l.CommitAuthorization(commitAllowEvent()); err != nil {
		t.Fatalf("CommitAuthorization: %v", err)
	}
	if len(order) != 2 || order[0] != "write" || order[1] != "sync" {
		t.Fatalf("expected write before sync, got %v", order)
	}
	if syncSeenChain != before {
		t.Fatalf("sync observed chain index %d, want pre-advance %d", syncSeenChain, before)
	}
	if l.chainIndex != before+1 {
		t.Fatalf("chain index advanced to %d, want %d", l.chainIndex, before+1)
	}
}

// assertPoisoned verifies the sink latched, chain state did not advance, and
// no further writes occur after a failed commit/Log.
func assertPoisoned(t *testing.T, l *Logger, writes int, beforeIndex uint64, beforePrev string) {
	t.Helper()
	if !l.poisoned {
		t.Fatal("logger must be poisoned after failure")
	}
	if l.chainIndex != beforeIndex || l.prevHash != beforePrev {
		t.Fatal("chain state must not advance after failure")
	}
	if err := l.CommitAuthorization(commitAllowEvent()); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("poisoned commit must return ErrAuditSinkUnhealthy, got %v", err)
	}
	if err := l.Log(commitAllowEvent()); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("poisoned Log must return ErrAuditSinkUnhealthy, got %v", err)
	}
	if writes != 1 {
		t.Fatalf("no further writes allowed after poison, got %d", writes)
	}
}

func TestCommitAuthorizationShortWritePoisonsWithoutAdvancing(t *testing.T) {
	l := newCommitLogger(t)

	writes := 0
	l.writeFn = func(b []byte) (int, error) {
		writes++
		return len(b) - 1, nil
	}

	beforeIndex := l.chainIndex
	beforePrev := l.prevHash
	if err := l.CommitAuthorization(commitAllowEvent()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got %v", err)
	}
	assertPoisoned(t, l, writes, beforeIndex, beforePrev)
}

func TestCommitAuthorizationSyncFailurePoisonsWithoutAdvancing(t *testing.T) {
	l := newCommitLogger(t)

	writes := 0
	l.writeFn = func(b []byte) (int, error) {
		writes++
		return len(b), nil
	}
	l.syncFn = func() error {
		return errors.New("sync failed")
	}

	beforeIndex := l.chainIndex
	beforePrev := l.prevHash
	if err := l.CommitAuthorization(commitAllowEvent()); err == nil {
		t.Fatal("expected sync failure error")
	}
	assertPoisoned(t, l, writes, beforeIndex, beforePrev)
}

func TestCommitAuthorizationRejectsNonAllowAndNonDurableSink(t *testing.T) {
	l := newCommitLogger(t)
	writes := 0
	l.writeFn = func(b []byte) (int, error) {
		writes++
		return len(b), nil
	}

	if err := l.CommitAuthorization(Event{EventType: EventToolDenied, Decision: "deny"}); err == nil {
		t.Fatal("expected rejection of non-allow event")
	}
	if err := l.CommitAuthorization(Event{EventType: EventToolAllowed, Decision: "deny"}); err == nil {
		t.Fatal("expected rejection of allow event with non-allow decision")
	}
	if writes != 0 || l.chainIndex != 0 {
		t.Fatalf("rejected events must not write or advance chain, writes=%d chain=%d", writes, l.chainIndex)
	}

	// stderr fallback is not durable and must fail closed without writing.
	fallback := MustLogger("")
	if fallback.durable {
		t.Fatal("stderr fallback must be non-durable")
	}
	if err := fallback.CommitAuthorization(commitAllowEvent()); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("non-durable sink commit must fail closed, got %v", err)
	}
	if fallback.chainIndex != 0 {
		t.Fatalf("non-durable sink must not advance chain, got %d", fallback.chainIndex)
	}
}

func TestLogShortWriteReturnsErrorAndPoisons(t *testing.T) {
	l := newCommitLogger(t)

	writes := 0
	l.writeFn = func(b []byte) (int, error) {
		writes++
		return len(b) - 1, nil
	}

	beforeIndex := l.chainIndex
	if err := l.Log(commitAllowEvent()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite from Log, got %v", err)
	}
	// A partial record cannot be followed by an authorization commit: Log must
	// return the error, poison the sink, and leave chain state untouched.
	assertPoisoned(t, l, writes, beforeIndex, "")
}
