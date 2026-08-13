package audit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCommitAuthorizationShortWriteDoesNotAdvanceChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	prevHash := l.prevHash
	chainIndex := l.chainIndex
	l.write = func(f *os.File, data []byte) (int, error) {
		if len(data) == 0 {
			return 0, nil
		}
		return len(data) - 1, nil
	}

	err = l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-short",
		Tool:      "file_read",
		Decision:  "allow",
	})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: want io.ErrShortWrite, got %v", err)
	}
	if !l.poisoned {
		t.Fatal("logger must be poisoned after short write")
	}
	if l.prevHash != prevHash {
		t.Fatalf("prevHash advanced after short write: got %q want %q", l.prevHash, prevHash)
	}
	if l.chainIndex != chainIndex {
		t.Fatalf("chainIndex advanced after short write: got %d want %d", l.chainIndex, chainIndex)
	}

	l.write = (*os.File).Write
	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-short",
		Tool:      "file_read",
		Decision:  "allow",
	}); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("commit after short-write poison: want ErrAuditSinkUnhealthy, got %v", err)
	}
}

func TestCommitAuthorizationWriteFailurePoisonsLoggerInternal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	prevHash := l.prevHash
	chainIndex := l.chainIndex
	injected := errors.New("injected sink failure")
	l.write = func(f *os.File, data []byte) (int, error) {
		return 0, injected
	}

	err = l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-poison",
		Tool:      "file_read",
		Decision:  "allow",
	})
	if !errors.Is(err, injected) {
		t.Fatalf("first commit: want injected error, got %v", err)
	}
	if !l.poisoned {
		t.Fatal("logger must be poisoned after write failure")
	}
	if l.prevHash != prevHash || l.chainIndex != chainIndex {
		t.Fatalf("chain advanced after write failure: prevHash=%q chainIndex=%d", l.prevHash, l.chainIndex)
	}

	l.write = (*os.File).Write
	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-poison",
		Tool:      "file_read",
		Decision:  "allow",
	}); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("second commit: want ErrAuditSinkUnhealthy, got %v", err)
	}
}
