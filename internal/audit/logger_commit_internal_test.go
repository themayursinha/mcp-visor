package audit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
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

// TestNewLoggerSyncsParentDirOnCreate proves the Codex P1 directory-sync fix:
// when NewLogger creates a fresh audit file, the parent directory must be
// synced (making the filename->inode entry durable) before any authorization
// commit is permitted. The sync must happen exactly once on creation and not
// on reopens of an existing file.
func TestNewLoggerSyncsParentDirOnCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	var (
		mu         sync.Mutex
		syncedDirs []string
	)
	syncDir = func(f *os.File) error {
		mu.Lock()
		defer mu.Unlock()
		syncedDirs = append(syncedDirs, f.Name())
		return f.Sync()
	}
	t.Cleanup(func() { syncDir = (*os.File).Sync })

	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger (create): %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	mu.Lock()
	createdSyncs := append([]string(nil), syncedDirs...)
	mu.Unlock()
	if len(createdSyncs) != 1 {
		t.Fatalf("parent dir sync on create: want 1, got %d (%v)", len(createdSyncs), createdSyncs)
	}
	if createdSyncs[0] != dir {
		t.Fatalf("parent dir sync: want %q, got %q", dir, createdSyncs[0])
	}

	// Reopen the existing file: the directory entry already exists, so no
	// additional directory sync is permitted.
	reopened, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger (reopen): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	mu.Lock()
	totalSyncs := len(syncedDirs)
	mu.Unlock()
	if totalSyncs != 1 {
		t.Fatalf("directory sync on reopen of existing file: want 1 total, got %d", totalSyncs)
	}

	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-sync",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("commit after create+sync: %v", err)
	}
}

// TestNewLoggerFailClosedOnParentDirSyncError proves the fail-closed half of
// the Codex P1 fix: if the parent directory cannot be synced after creating
// the audit file, NewLogger must refuse to start (an authorization commit must
// never be permitted while the audit entry may vanish on reboot).
func TestNewLoggerFailClosedOnParentDirSyncError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	syncErr := errors.New("injected parent dir sync failure")
	syncDir = func(f *os.File) error { return syncErr }
	t.Cleanup(func() { syncDir = (*os.File).Sync })

	if _, err := NewLogger(path); !errors.Is(err, syncErr) {
		t.Fatalf("NewLogger with failing parent dir sync: want injected error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("fail-closed NewLogger must not leave a half-created audit file (got %v)", err)
	}
}

// TestNewLoggerSyncsParentDirWhenFileRotatedBeforeOpen proves create detection
// is atomic with the open: if the ledger is rotated away after chain recovery
// and before open, NewLogger must still fsync the parent directory for the
// new inode. A pre-open Stat TOCTOU would see the old file, skip dir sync,
// and leave the replacement entry non-durable.
func TestNewLoggerSyncsParentDirWhenFileRotatedBeforeOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rotated := []byte(`{"event_type":"session_started","session_id":"rotated","policy_decision":"n/a"}` + "\n")
	if err := os.WriteFile(path, rotated, 0o600); err != nil {
		t.Fatalf("pre-create audit file: %v", err)
	}

	var (
		mu         sync.Mutex
		syncedDirs []string
	)
	syncDir = func(f *os.File) error {
		mu.Lock()
		defer mu.Unlock()
		syncedDirs = append(syncedDirs, f.Name())
		return f.Sync()
	}
	t.Cleanup(func() { syncDir = (*os.File).Sync })

	origOpen := openFile
	t.Cleanup(func() { openFile = origOpen })
	openFile = func(p string, flags int, perm os.FileMode) (*os.File, error) {
		_ = os.Remove(path)
		return origOpen(p, flags, perm)
	}

	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger after rotation-before-open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	mu.Lock()
	gotSyncs := append([]string(nil), syncedDirs...)
	mu.Unlock()
	if len(gotSyncs) != 1 {
		t.Fatalf("parent dir sync after rotation-before-open: want 1, got %d (%v)", len(gotSyncs), gotSyncs)
	}
	if gotSyncs[0] != dir {
		t.Fatalf("parent dir sync: want %q, got %q", dir, gotSyncs[0])
	}
}

// TestNewLoggerDoesNotUnlinkForeignFileOnSyncFailure proves cleanup never
// unlinks a ledger this call did not create. If another process creates the
// file in the TOCTOU window between Stat and open, fail-closed dir-sync
// cleanup must not Remove that foreign inode.
func TestNewLoggerDoesNotUnlinkForeignFileOnSyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	foreign := []byte(`{"event_type":"session_started","session_id":"foreign","policy_decision":"n/a"}` + "\n")

	syncErr := errors.New("injected parent dir sync failure")
	var syncCalls int
	syncDir = func(f *os.File) error {
		syncCalls++
		return syncErr
	}
	t.Cleanup(func() { syncDir = (*os.File).Sync })

	origOpen := openFile
	t.Cleanup(func() { openFile = origOpen })
	var openCalls int
	openFile = func(p string, flags int, perm os.FileMode) (*os.File, error) {
		openCalls++
		if openCalls == 1 {
			if err := os.WriteFile(path, foreign, 0o600); err != nil {
				return nil, err
			}
		}
		return origOpen(p, flags, perm)
	}

	l, err := NewLogger(path)
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("foreign audit file was unlinked: %v (NewLogger err: %v)", readErr, err)
	}
	if string(got) != string(foreign) {
		t.Fatalf("foreign audit content: got %q want %q", got, foreign)
	}
	if syncCalls != 0 {
		t.Fatalf("syncDir calls for a file this call did not create: want 0, got %d", syncCalls)
	}
	if err != nil {
		t.Fatalf("NewLogger (foreign file in TOCTOU window): %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
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
