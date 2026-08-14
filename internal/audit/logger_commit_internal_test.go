package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// TestNewLoggerSyncsParentDirForEveryAcceptedBinding proves the round-5
// constructor-acceptance durability: every accepted constructor binding
// (fresh exclusive-create or reopened existing inode) fsyncs the parent
// directory exactly once before NewLogger returns. The directory entry for a
// freshly created file must be durable before any authorization commit is
// permitted, and a retained/reopened existing binding must be re-synced so a
// later retry after a transient sync failure can leave the created inode in
// place safely.
func TestNewLoggerSyncsParentDirForEveryAcceptedBinding(t *testing.T) {
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

	// Reopen the existing file: the retained existing binding is accepted
	// only through another parent-directory sync, so a later retry after a
	// transient sync failure can safely resync the same inode in place.
	reopened, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger (reopen): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	mu.Lock()
	totalSyncs := len(syncedDirs)
	mu.Unlock()
	if totalSyncs != 2 {
		t.Fatalf("constructor acceptance sync on create+reopen: want 2 total, got %d", totalSyncs)
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
	// Round 5: a constructor sync failure never pathname-unlinks anything.
	// The just-created empty pathname may remain; a later successful
	// constructor revalidates and resyncs an existing binding.
	if fi, statErr := os.Stat(path); statErr == nil {
		if fi.Size() != 0 {
			t.Fatalf("sync-failure constructor must leave an empty audit pathname, got size %d", fi.Size())
		}
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("stat after constructor sync failure: %v", statErr)
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

	_, err := NewLogger(path)
	if err == nil {
		t.Fatalf("NewLogger with failing parent dir sync on an existing foreign binding: want error, got nil")
	}
	if !errors.Is(err, syncErr) {
		t.Fatalf("NewLogger error on existing foreign binding: want injected sync error, got %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("foreign audit file was unlinked: %v", readErr)
	}
	if string(got) != string(foreign) {
		t.Fatalf("foreign audit content: got %q want %q", got, foreign)
	}
	// Round 5: the retained existing binding is accepted only through a
	// constructor parent-directory sync, which fails closed here; the foreign
	// inode must remain untouched (no pathname removal).
	if syncCalls != 1 {
		t.Fatalf("constructor acceptance sync for existing foreign binding: want 1, got %d", syncCalls)
	}
}

// TestNewLoggerFallbackNeverCreatesUnsyncedFile proves the Codex P1 EEXIST
// fallback cannot silently create an unsynced directory entry: if the ledger
// is rotated away after exclusive-create returns EEXIST and before the
// existing-file fallback open, that fallback must not use O_CREATE (which
// would make a new inode while created stays false and skip syncParentDir).
// The exclusive-create path must be retried so the parent dir is synced.
func TestNewLoggerFallbackNeverCreatesUnsyncedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	seed := []byte(`{"event_type":"session_started","session_id":"seed","policy_decision":"n/a"}` + "\n")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatalf("seed audit file: %v", err)
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
	var (
		openCalls     int
		fallbackFlags int
	)
	openFile = func(p string, flags int, perm os.FileMode) (*os.File, error) {
		openCalls++
		if openCalls == 2 {
			fallbackFlags = flags
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		}
		return origOpen(p, flags, perm)
	}

	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger after rotation-between-EEXIST-and-fallback: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if fallbackFlags&os.O_CREATE != 0 {
		t.Fatalf("EEXIST fallback open flags must not contain O_CREATE (got %d)", fallbackFlags)
	}

	mu.Lock()
	gotSyncs := append([]string(nil), syncedDirs...)
	mu.Unlock()
	if len(gotSyncs) != 1 {
		t.Fatalf("parent dir sync after exclusive-create retry: want 1, got %d (%v)", len(gotSyncs), gotSyncs)
	}
	if gotSyncs[0] != dir {
		t.Fatalf("parent dir sync: want %q, got %q", dir, gotSyncs[0])
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

// ---------------------------------------------------------------------------
// H19 round 4: rotation-while-running durability.
// All RED tests in this section must FAIL on the vulnerable baseline
// (7fb07ad) for the intended reason: stale constructor chain state is carried
// onto a fresh inode, or a running logger authorizes a commit after its
// configured path has been rotated/rebound.
// ---------------------------------------------------------------------------

// readLedgerLines decodes a JSONL ledger file into non-empty lines.
func readLedgerLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func decodeLedgerEvent(t *testing.T, line string) Event {
	t.Helper()
	var ev Event
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("decode ledger event: %v\nline=%s", err, line)
	}
	return ev
}

// seedHashedLedger writes one valid hashed tool_call_allowed record to a
// fresh ledger at path and returns its tip (hash + chain index). The ledger
// is produced through the real logger before any global seam is installed, so
// recovery must see a verified hashed tip.
func seedHashedLedger(t *testing.T, path, sessionID string) (tipHash string, tipChain uint64) {
	t.Helper()
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("seed NewLogger(%s): %v", path, err)
	}
	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: sessionID,
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	lines := readLedgerLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("seed ledger %s: want 1 line, got %d", path, len(lines))
	}
	ev := decodeLedgerEvent(t, lines[0])
	if ev.Hash == "" {
		t.Fatalf("seed ledger %s: tip record missing hash", path)
	}
	return ev.Hash, ev.ChainIndex
}

// TestNewLoggerFreshCreateStartsGenesisAfterRecoveredLedgerRemoved proves a
// fresh inode created after an old hashed path disappears starts at genesis:
// no recovered prevHash/chainIndex may cross onto the new inode. On the
// baseline, recoverChainState(path) reads the old hashed ledger, the openFile
// seam removes it before the first O_EXCL open, and the fresh B carries A's
// chain state.
func TestNewLoggerFreshCreateStartsGenesisAfterRecoveredLedgerRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	seedHashedLedger(t, path, "sess-removed-a")

	origOpen := openFile
	t.Cleanup(func() { openFile = origOpen })
	openFile = func(p string, flags int, perm os.FileMode) (*os.File, error) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		return origOpen(p, flags, perm)
	}

	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger after recovered ledger removed: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-fresh-b",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("commit on fresh inode: %v", err)
	}
	lines := readLedgerLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("fresh ledger: want 1 line, got %d", len(lines))
	}
	ev := decodeLedgerEvent(t, lines[0])
	if ev.ChainIndex != 0 {
		t.Fatalf("fresh inode first record chain_index=%d, want 0 (must not carry removed ledger's chain)", ev.ChainIndex)
	}
	if ev.PrevHash != "" {
		t.Fatalf("fresh inode first record prev_hash=%q, want empty (must not carry removed ledger's chain)", ev.PrevHash)
	}
}

// TestNewLoggerRecoversFromActuallyOpenedReplacementAfterEEXIST proves the
// fallback recovers chain state from the inode it actually opens. On the
// baseline, recovery reads A before open; the openFile seam installs an
// independently hashed B after the O_EXCL EEXIST; the fallback opens B but
// appends A-linked metadata into B.
func TestNewLoggerRecoversFromActuallyOpenedReplacementAfterEEXIST(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	seedHashedLedger(t, path, "sess-eeexist-a")

	bPath := filepath.Join(dir, "replacement.jsonl")
	bTipHash, bTipChain := seedHashedLedger(t, bPath, "sess-eeexist-b")

	origOpen := openFile
	t.Cleanup(func() { openFile = origOpen })
	openCalls := 0
	openFile = func(p string, flags int, perm os.FileMode) (*os.File, error) {
		openCalls++
		if openCalls == 2 {
			// Between the O_EXCL EEXIST and the existing-file fallback open,
			// atomically replace the configured path with independently
			// hashed B.
			if err := os.Rename(bPath, path); err != nil {
				return nil, err
			}
		}
		return origOpen(p, flags, perm)
	}

	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger with replacement after EEXIST: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-after-replace",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("commit on replacement inode: %v", err)
	}
	lines := readLedgerLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("replacement ledger: want 2 lines (B tip + new), got %d", len(lines))
	}
	ev := decodeLedgerEvent(t, lines[len(lines)-1])
	if ev.PrevHash != bTipHash {
		t.Fatalf("appended record prev_hash=%q, want replacement tip %q (must continue B, not A)", ev.PrevHash, bTipHash)
	}
	if ev.ChainIndex != bTipChain+1 {
		t.Fatalf("appended record chain_index=%d, want %d (B tip+1)", ev.ChainIndex, bTipChain+1)
	}
}

// TestNewLoggerRecoversConcurrentLedgerCreatedBeforeExclusiveOpen proves that
// when recovery initially sees ENOENT but a concurrent non-empty hashed
// ledger wins before the first O_EXCL (so O_EXCL returns EEXIST and the
// fallback opens it), the next record continues that ledger's verified tip
// instead of starting at genesis. On the baseline, genesis state is used on
// the concurrently installed B.
func TestNewLoggerRecoversConcurrentLedgerCreatedBeforeExclusiveOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	bPath := filepath.Join(dir, "concurrent.jsonl")
	bTipHash, bTipChain := seedHashedLedger(t, bPath, "sess-concurrent-b")

	origOpen := openFile
	t.Cleanup(func() { openFile = origOpen })
	openCalls := 0
	openFile = func(p string, flags int, perm os.FileMode) (*os.File, error) {
		openCalls++
		if openCalls == 1 {
			// Install B before the first exclusive open: recovery would have
			// seen ENOENT, but the concurrent creator wins the race.
			if err := os.Rename(bPath, path); err != nil {
				return nil, err
			}
		}
		return origOpen(p, flags, perm)
	}

	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger with concurrent ledger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-concurrent-next",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("commit on concurrent inode: %v", err)
	}
	lines := readLedgerLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("concurrent ledger: want 2 lines (B tip + new), got %d", len(lines))
	}
	ev := decodeLedgerEvent(t, lines[len(lines)-1])
	if ev.PrevHash != bTipHash {
		t.Fatalf("appended record prev_hash=%q, want concurrent tip %q", ev.PrevHash, bTipHash)
	}
	if ev.ChainIndex != bTipChain+1 {
		t.Fatalf("appended record chain_index=%d, want %d (concurrent tip+1)", ev.ChainIndex, bTipChain+1)
	}
}

// TestNewLoggerExclusiveRetryStartsGenesis proves the EEXIST->ENOENT retry
// creates a fresh inode that starts at genesis (in addition to the existing
// exactly-once parent-directory sync). On the baseline, the retry-created B
// carries A's recovered chain.
func TestNewLoggerExclusiveRetryStartsGenesis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	seedHashedLedger(t, path, "sess-retry-a")

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
	openCalls := 0
	openFile = func(p string, flags int, perm os.FileMode) (*os.File, error) {
		openCalls++
		if openCalls == 2 {
			// Between EEXIST and the existing-file fallback, the path is
			// rotated away so the fallback sees ENOENT and the retry
			// exclusive-create creates a fresh inode.
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		}
		return origOpen(p, flags, perm)
	}

	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger after EEXIST->ENOENT retry: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	mu.Lock()
	gotSyncs := append([]string(nil), syncedDirs...)
	mu.Unlock()
	if len(gotSyncs) != 1 {
		t.Fatalf("parent dir sync after exclusive-create retry: want 1, got %d (%v)", len(gotSyncs), gotSyncs)
	}
	if gotSyncs[0] != dir {
		t.Fatalf("parent dir sync: want %q, got %q", dir, gotSyncs[0])
	}

	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-retry-b",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("commit on retry-created inode: %v", err)
	}
	lines := readLedgerLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("retry-created ledger: want 1 line, got %d", len(lines))
	}
	ev := decodeLedgerEvent(t, lines[0])
	if ev.ChainIndex != 0 {
		t.Fatalf("retry-created inode first record chain_index=%d, want 0 (must not carry removed ledger's chain)", ev.ChainIndex)
	}
	if ev.PrevHash != "" {
		t.Fatalf("retry-created inode first record prev_hash=%q, want empty (must not carry removed ledger's chain)", ev.PrevHash)
	}
}

// TestCommitAuthorizationRejectsPathRotation proves live path-to-fd identity
// validation: any rotation/rebinding of the configured audit path between
// logger construction and an authorization commit must fail closed, poison
// the logger, and leave in-memory chain state untouched. On the baseline,
// CommitAuthorization writes through the stale fd and returns success.
func TestCommitAuthorizationRejectsPathRotation(t *testing.T) {
	tests := []struct {
		name    string
		wantErr error
		mutate  func(t *testing.T, path string)
	}{
		{"rename_away", ErrAuditSinkChanged, func(t *testing.T, path string) {
			if err := os.Rename(path, path+".backup"); err != nil {
				t.Fatalf("rename away: %v", err)
			}
		}},
		{"unlink", ErrAuditSinkChanged, func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatalf("unlink: %v", err)
			}
		}},
		{"regular_replacement", ErrAuditSinkChanged, func(t *testing.T, path string) {
			if err := os.Rename(path, path+".backup"); err != nil {
				t.Fatalf("rename away: %v", err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatalf("fresh replacement: %v", err)
			}
		}},
		{"atomic_rename_over", ErrAuditSinkChanged, func(t *testing.T, path string) {
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, nil, 0o600); err != nil {
				t.Fatalf("temp replacement: %v", err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatalf("atomic rename over: %v", err)
			}
		}},
		{"symlink_to_different_inode", ErrAuditSinkChanged, func(t *testing.T, path string) {
			target := path + ".other"
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatalf("target file: %v", err)
			}
			if err := os.Rename(path, path+".backup"); err != nil {
				t.Fatalf("rename away: %v", err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"non_regular_replacement", ErrNonDurableSink, func(t *testing.T, path string) {
			if err := os.Rename(path, path+".backup"); err != nil {
				t.Fatalf("rename away: %v", err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatalf("directory replacement: %v", err)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			l, err := NewLogger(path)
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			t.Cleanup(func() { _ = l.Close() })

			// Warm the chain so a rotated commit could carry a candidate
			// record and advance state.
			if err := l.CommitAuthorization(Event{
				EventType: EventToolAllowed,
				SessionID: "sess-warm",
				Tool:      "file_read",
				Decision:  "allow",
			}); err != nil {
				t.Fatalf("warmup commit: %v", err)
			}
			prevHash := l.prevHash
			chainIndex := l.chainIndex

			tt.mutate(t, path)

			err = l.CommitAuthorization(Event{
				EventType: EventToolAllowed,
				SessionID: "sess-rotated",
				Tool:      "file_read",
				Decision:  "allow",
			})
			if err == nil {
				t.Fatalf("commit after %s: want error, got nil (stale fd authorized)", tt.name)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("commit after %s: want %v, got %v", tt.name, tt.wantErr, err)
			}
			if !l.poisoned {
				t.Fatalf("logger must be poisoned after %s", tt.name)
			}
			if l.prevHash != prevHash || l.chainIndex != chainIndex {
				t.Fatalf("chain advanced after %s: prevHash=%q chainIndex=%d", tt.name, l.prevHash, l.chainIndex)
			}

			// No candidate record may land in the replacement or the
			// still-addressable rotated-away file.
			for _, p := range []string{path, path + ".backup", path + ".other"} {
				data, rerr := os.ReadFile(p)
				if rerr != nil {
					continue
				}
				for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
					if strings.TrimSpace(line) == "" {
						continue
					}
					ev := decodeLedgerEvent(t, line)
					if ev.EventType == EventToolAllowed && ev.SessionID == "sess-rotated" {
						t.Fatalf("candidate record for rotated attempt found in %s: %s", p, line)
					}
				}
			}

			// Poison is sticky: the next commit returns ErrAuditSinkUnhealthy
			// without attempting a filesystem write.
			l.write = func(*os.File, []byte) (int, error) {
				t.Fatal("poisoned logger must not attempt another write")
				return 0, nil
			}
			if err := l.CommitAuthorization(Event{
				EventType: EventToolAllowed,
				SessionID: "sess-after-poison",
				Tool:      "file_read",
				Decision:  "allow",
			}); !errors.Is(err, ErrAuditSinkUnhealthy) {
				t.Fatalf("commit after poison: want ErrAuditSinkUnhealthy, got %v", err)
			}
		})
	}
}

// TestCommitAuthorizationRejectsRotationDuringWrite proves the post-write
// identity check closes the check-then-write and write-then-return rotation
// windows: rotation injected inside the write seam fails closed even though
// the O_SYNC write itself succeeded on the (now stale) inode.
func TestCommitAuthorizationRejectsRotationDuringWrite(t *testing.T) {
	t.Run("rotate_before_write", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })

		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-warm",
			Tool:      "file_read",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("warmup commit: %v", err)
		}
		prevHash := l.prevHash
		chainIndex := l.chainIndex

		l.write = func(f *os.File, data []byte) (int, error) {
			if err := os.Rename(path, path+".backup"); err != nil {
				return 0, err
			}
			return (*os.File).Write(f, data)
		}

		err = l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-inwrite",
			Tool:      "file_read",
			Decision:  "allow",
		})
		if err == nil {
			t.Fatal("commit with rotation before write: want error, got nil")
		}
		if !errors.Is(err, ErrAuditSinkChanged) {
			t.Fatalf("commit with rotation before write: want ErrAuditSinkChanged, got %v", err)
		}
		if !l.poisoned {
			t.Fatal("logger must be poisoned after rotation before write")
		}
		if l.prevHash != prevHash || l.chainIndex != chainIndex {
			t.Fatalf("chain advanced: prevHash=%q chainIndex=%d", l.prevHash, l.chainIndex)
		}

		l.write = (*os.File).Write
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-after-poison",
			Tool:      "file_read",
			Decision:  "allow",
		}); !errors.Is(err, ErrAuditSinkUnhealthy) {
			t.Fatalf("commit after poison: want ErrAuditSinkUnhealthy, got %v", err)
		}
	})

	t.Run("rotate_after_write", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })

		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-warm",
			Tool:      "file_read",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("warmup commit: %v", err)
		}
		prevHash := l.prevHash
		chainIndex := l.chainIndex

		l.write = func(f *os.File, data []byte) (int, error) {
			n, werr := (*os.File).Write(f, data)
			if rerr := os.Rename(path, path+".backup"); rerr != nil {
				return n, rerr
			}
			return n, werr
		}

		err = l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-inwrite",
			Tool:      "file_read",
			Decision:  "allow",
		})
		if err == nil {
			t.Fatal("commit with rotation after write: want error, got nil")
		}
		if !errors.Is(err, ErrAuditSinkChanged) {
			t.Fatalf("commit with rotation after write: want ErrAuditSinkChanged, got %v", err)
		}
		if !l.poisoned {
			t.Fatal("logger must be poisoned after rotation after write")
		}
		if l.prevHash != prevHash || l.chainIndex != chainIndex {
			t.Fatalf("chain advanced: prevHash=%q chainIndex=%d", l.prevHash, l.chainIndex)
		}

		l.write = (*os.File).Write
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-after-poison",
			Tool:      "file_read",
			Decision:  "allow",
		}); !errors.Is(err, ErrAuditSinkUnhealthy) {
			t.Fatalf("commit after poison: want ErrAuditSinkUnhealthy, got %v", err)
		}
	})
}

// TestCommitAuthorizationAllowsStableAndSameInodeHardLinkBinding is the
// healthy control: a stable configured path and a same-inode hard-link rebind
// are identity-preserving regular directory entries and must still commit.
// A symlink is never a healthy identity-preserving binding, even when it
// resolves to the opened inode; that case is covered by
// TestCommitAuthorizationRejectsSameInodeSymlinkRebind.
func TestCommitAuthorizationAllowsStableAndSameInodeHardLinkBinding(t *testing.T) {
	t.Run("stable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-stable",
			Tool:      "file_read",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("commit on stable path: %v", err)
		}
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-stable-2",
			Tool:      "http_post",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("second commit on stable path: %v", err)
		}
	})

	t.Run("hard_link_same_inode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-link",
			Tool:      "file_read",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("warmup commit: %v", err)
		}

		link := path + ".hard"
		if err := os.Link(path, link); err != nil {
			t.Fatalf("hard link: %v", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove original binding: %v", err)
		}
		if err := os.Rename(link, path); err != nil {
			t.Fatalf("rebind through hard link: %v", err)
		}

		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-link-2",
			Tool:      "http_post",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("commit after same-inode hard-link rebind: %v", err)
		}
	})
}

// TestCommitAuthorizationRejectsSameInodeSymlinkRebind proves commit-time
// path validation is no-follow: moving the opened ledger into another
// directory on the same filesystem and replacing the configured path with a
// symlink to that same inode must fail closed with ErrAuditSinkChanged,
// poison the logger, and leave target bytes and chain state unchanged.
// Rejection must happen in pre-write validation so the allow is never
// appended through the fd. On the vulnerable baseline, os.Stat follows the
// symlink, os.SameFile passes, and the commit succeeds while only
// configured/ is fsynced.
func TestCommitAuthorizationRejectsSameInodeSymlinkRebind(t *testing.T) {
	root := t.TempDir()
	configuredDir := filepath.Join(root, "configured")
	targetDir := filepath.Join(root, "target")
	if err := os.Mkdir(configuredDir, 0o700); err != nil {
		t.Fatalf("mkdir configured: %v", err)
	}
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	configuredPath := filepath.Join(configuredDir, "audit.jsonl")
	targetPath := filepath.Join(targetDir, "audit.jsonl")

	l, err := NewLogger(configuredPath)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-warm",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("warmup commit: %v", err)
	}

	if err := os.Rename(configuredPath, targetPath); err != nil {
		t.Fatalf("rename ledger into target dir: %v", err)
	}
	if err := os.Symlink(targetPath, configuredPath); err != nil {
		t.Fatalf("symlink configured path to moved inode: %v", err)
	}

	linkInfo, err := os.Lstat(configuredPath)
	if err != nil {
		t.Fatalf("lstat configured path: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("configured path is not a symlink")
	}
	fdInfo, err := l.file.Stat()
	if err != nil {
		t.Fatalf("stat logger fd: %v", err)
	}
	followed, err := os.Stat(configuredPath)
	if err != nil {
		t.Fatalf("stat through symlink: %v", err)
	}
	if !os.SameFile(fdInfo, followed) {
		t.Fatal("symlink does not resolve to the logger fd inode (would be a different-inode swap)")
	}

	before, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("snapshot target bytes: %v", err)
	}
	prevHash := l.prevHash
	chainIndex := l.chainIndex

	err = l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-symlink-rebind",
		Tool:      "http_post",
		Decision:  "allow",
	})
	if err == nil {
		t.Fatal("commit after same-inode symlink rebind: want ErrAuditSinkChanged, got nil")
	}
	if !errors.Is(err, ErrAuditSinkChanged) {
		t.Fatalf("commit after same-inode symlink rebind: want ErrAuditSinkChanged, got %v", err)
	}
	if !l.poisoned {
		t.Fatal("logger must be poisoned after same-inode symlink rebind")
	}
	after, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read target bytes after commit: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("target bytes changed after rejected symlink rebind (write was not pre-validation)")
	}
	if l.prevHash != prevHash || l.chainIndex != chainIndex {
		t.Fatalf("chain advanced after same-inode symlink rebind: prevHash=%q chainIndex=%d", l.prevHash, l.chainIndex)
	}

	l.write = func(*os.File, []byte) (int, error) {
		t.Fatal("poisoned logger must not attempt another write")
		return 0, nil
	}
	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-after-poison",
		Tool:      "file_read",
		Decision:  "allow",
	}); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("commit after poison: want ErrAuditSinkUnhealthy, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// H19 round 5: rebind directory-sync, Log-after-poison, pathname cleanup, and
// constructor no-follow. All RED tests in this section must FAIL on the
// vulnerable baseline (f3828956) for the intended reason: a same-inode rebind
// authorizes with zero parent-dir sync, ordinary Log appends after poison,
// constructor sync-failure cleanup unlinks a replacement, or constructor
// opens follow a pre-existing symlink.
// ---------------------------------------------------------------------------

// TestCommitAuthorizationSyncsParentDirForSameInodeHardLinkRebind proves a
// same-inode hard-link rebind is accepted only through the parent-directory
// durability boundary: at least one fsync of the configured parent must occur
// after the rebind and before a successful commit return. A symlink rebind is
// not a healthy identity-preserving binding.
func TestCommitAuthorizationSyncsParentDirForSameInodeHardLinkRebind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-warm",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("warmup commit: %v", err)
	}

	var (
		mu         sync.Mutex
		postRebind int
	)
	syncDir = func(f *os.File) error {
		mu.Lock()
		defer mu.Unlock()
		postRebind++
		return f.Sync()
	}
	t.Cleanup(func() { syncDir = (*os.File).Sync })

	link := path + ".hard"
	if err := os.Link(path, link); err != nil {
		t.Fatalf("hard link: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove original binding: %v", err)
	}
	if err := os.Rename(link, path); err != nil {
		t.Fatalf("rebind through hard link: %v", err)
	}

	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-rebound",
		Tool:      "http_post",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("commit after same-inode hard-link rebind: %v", err)
	}

	mu.Lock()
	got := postRebind
	mu.Unlock()
	if got < 1 {
		t.Fatalf("same-inode hard-link rebind authorized with zero parent-dir syncs (got %d)", got)
	}
	lines := readLedgerLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("ledger after hard-link rebind: want 2 linked records, got %d", len(lines))
	}
}

// TestCommitAuthorizationSameInodeHardLinkRebindSyncFailurePoisons proves a
// parent-dir sync failure during the post-rebind hard-link binding validation
// poisons the logger, leaves chain state unchanged, and makes every later
// commit return ErrAuditSinkUnhealthy without another write.
func TestCommitAuthorizationSameInodeHardLinkRebindSyncFailurePoisons(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-warm",
		Tool:      "file_read",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("warmup commit: %v", err)
	}

	link := path + ".hard"
	if err := os.Link(path, link); err != nil {
		t.Fatalf("hard link: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove original binding: %v", err)
	}
	if err := os.Rename(link, path); err != nil {
		t.Fatalf("rebind through hard link: %v", err)
	}

	prevHash := l.prevHash
	chainIndex := l.chainIndex
	syncErr := errors.New("injected parent dir sync failure")
	syncDir = func(*os.File) error { return syncErr }
	t.Cleanup(func() { syncDir = (*os.File).Sync })

	err = l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-syncfail",
		Tool:      "http_post",
		Decision:  "allow",
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("commit with failing rebind dir sync: want injected error, got %v", err)
	}
	if !l.poisoned {
		t.Fatal("logger must be poisoned after rebind dir-sync failure")
	}
	if l.prevHash != prevHash || l.chainIndex != chainIndex {
		t.Fatalf("chain advanced after rebind dir-sync failure: prevHash=%q chainIndex=%d", l.prevHash, l.chainIndex)
	}

	l.write = func(*os.File, []byte) (int, error) {
		t.Fatal("poisoned logger must not attempt another write")
		return 0, nil
	}
	if err := l.CommitAuthorization(Event{
		EventType: EventToolAllowed,
		SessionID: "sess-after-poison",
		Tool:      "file_read",
		Decision:  "allow",
	}); !errors.Is(err, ErrAuditSinkUnhealthy) {
		t.Fatalf("commit after poison: want ErrAuditSinkUnhealthy, got %v", err)
	}
}

// TestLogRefusesAfterPoison proves ordinary Log writes are blocked after any
// poison source: a short-write poison or a post-write binding poison must make
// Log return ErrAuditSinkUnhealthy without appending, without advancing chain
// state, and without touching the file.
func TestLogRefusesAfterPoison(t *testing.T) {
	t.Run("short_write_poison", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })

		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read ledger before: %v", err)
		}
		prevHash := l.prevHash
		chainIndex := l.chainIndex

		l.write = func(f *os.File, data []byte) (int, error) {
			return len(data) - 1, nil
		}
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-short",
			Tool:      "file_read",
			Decision:  "allow",
		}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short-write commit: want io.ErrShortWrite, got %v", err)
		}
		if !l.poisoned {
			t.Fatal("logger must be poisoned after short write")
		}

		l.write = func(*os.File, []byte) (int, error) {
			t.Fatal("poisoned logger must not attempt a Log write")
			return 0, nil
		}
		if err := l.Log(Event{
			EventType: EventToolDenied,
			SessionID: "sess-log-after-poison",
			Tool:      "file_read",
			Decision:  "deny",
		}); !errors.Is(err, ErrAuditSinkUnhealthy) {
			t.Fatalf("Log after short-write poison: want ErrAuditSinkUnhealthy, got %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read ledger after: %v", err)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("ledger bytes changed after poisoned Log: before=%q after=%q", before, after)
		}
		if l.prevHash != prevHash || l.chainIndex != chainIndex {
			t.Fatalf("chain advanced after poisoned Log: prevHash=%q chainIndex=%d", l.prevHash, l.chainIndex)
		}
	})

	t.Run("post_write_binding_poison", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-warm",
			Tool:      "file_read",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("warmup commit: %v", err)
		}

		backup := path + ".backup"
		l.write = func(f *os.File, data []byte) (int, error) {
			n, werr := (*os.File).Write(f, data)
			if rerr := os.Rename(path, backup); rerr != nil {
				return n, rerr
			}
			return n, werr
		}
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-inwrite",
			Tool:      "http_post",
			Decision:  "allow",
		}); err == nil {
			t.Fatal("commit with rotation after write: want error, got nil")
		}
		if !l.poisoned {
			t.Fatal("logger must be poisoned after post-write rotation")
		}

		before, err := os.ReadFile(backup)
		if err != nil {
			t.Fatalf("read rotated-away ledger before: %v", err)
		}
		prevHash := l.prevHash
		chainIndex := l.chainIndex

		l.write = func(*os.File, []byte) (int, error) {
			t.Fatal("poisoned logger must not attempt a Log write")
			return 0, nil
		}
		if err := l.Log(Event{
			EventType: EventToolDenied,
			SessionID: "sess-log-after-poison",
			Tool:      "file_read",
			Decision:  "deny",
		}); !errors.Is(err, ErrAuditSinkUnhealthy) {
			t.Fatalf("Log after post-write poison: want ErrAuditSinkUnhealthy, got %v", err)
		}
		after, err := os.ReadFile(backup)
		if err != nil {
			t.Fatalf("read rotated-away ledger after: %v", err)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("rotated-away ledger bytes changed after poisoned Log: before=%q after=%q", before, after)
		}
		if l.prevHash != prevHash || l.chainIndex != chainIndex {
			t.Fatalf("chain advanced after poisoned Log: prevHash=%q chainIndex=%d", l.prevHash, l.chainIndex)
		}
	})
}

// TestNewLoggerDoesNotRemoveReplacementOnSyncFailure proves a constructor
// sync failure never pathname-unlinks anything: if the just-created audit
// path is atomically replaced while the parent-dir sync fails, the
// replacement pathname and its bytes must remain untouched.
func TestNewLoggerDoesNotRemoveReplacementOnSyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	replacement := filepath.Join(dir, "replacement.jsonl")
	sentinel := []byte("replacement-sentinel-content")

	if err := os.WriteFile(replacement, sentinel, 0o600); err != nil {
		t.Fatalf("prepare replacement: %v", err)
	}

	syncErr := errors.New("injected parent dir sync failure")
	syncDir = func(*os.File) error {
		if err := os.Rename(path, path+".removed"); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(replacement, path); err != nil {
			return err
		}
		return syncErr
	}
	t.Cleanup(func() { syncDir = (*os.File).Sync })

	if _, err := NewLogger(path); !errors.Is(err, syncErr) {
		t.Fatalf("NewLogger with sync failure after replacement: want injected error, got %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement pathname was removed by constructor cleanup: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("replacement bytes changed: got %q want %q", got, sentinel)
	}
}

// TestNewLoggerRejectsSymlinkSink proves every constructor open rejects a
// pre-existing symlink with kernel no-follow semantics: NewLogger must fail
// and the symlink target bytes must remain unchanged.
func TestNewLoggerRejectsSymlinkSink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim.jsonl")
	sentinel := []byte(`{"event_type":"session_started","session_id":"victim","policy_decision":"n/a"}` + "\n")
	if err := os.WriteFile(target, sentinel, 0o600); err != nil {
		t.Fatalf("write victim target: %v", err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink configured audit path to victim: %v", err)
	}

	if _, err := NewLogger(path); err == nil {
		t.Fatal("NewLogger over a pre-existing symlink: want error, got nil")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read victim target: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("symlink target bytes changed: got %q want %q", got, sentinel)
	}
}
