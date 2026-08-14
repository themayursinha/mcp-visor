package audit

import (
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

// TestCommitAuthorizationAllowsSameInodePathBinding is the healthy control:
// rebinding the configured path to the SAME inode (hard link or symlink) is
// identity-preserving and must still commit. It proves the live check is
// identity-based, not textual-path-based.
func TestCommitAuthorizationAllowsSameInodePathBinding(t *testing.T) {
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

	t.Run("symlink_same_inode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := NewLogger(path)
		if err != nil {
			t.Fatalf("NewLogger: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-sym",
			Tool:      "file_read",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("warmup commit: %v", err)
		}

		backup := path + ".backup"
		if err := os.Rename(path, backup); err != nil {
			t.Fatalf("rename away: %v", err)
		}
		if err := os.Symlink(backup, path); err != nil {
			t.Fatalf("symlink to same inode: %v", err)
		}

		if err := l.CommitAuthorization(Event{
			EventType: EventToolAllowed,
			SessionID: "sess-sym-2",
			Tool:      "http_post",
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("commit after same-inode symlink rebind: %v", err)
		}
	})
}
