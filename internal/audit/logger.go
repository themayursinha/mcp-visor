package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/themayursinha/mcp-visor/internal/policy"
)

var (
	// ErrIncompleteAuditTail is returned when an existing audit log ends mid-record.
	ErrIncompleteAuditTail = errors.New("audit log incomplete trailing line")
	// ErrCorruptAuditRecord is returned when the last complete audit record is invalid.
	ErrCorruptAuditRecord = errors.New("audit log corrupt last record")
	// ErrNonDurableSink is returned when authorization commit is attempted on a
	// sink that is not a regular O_SYNC file opened by NewLogger, or when the
	// configured audit path is rebound to a non-regular object at commit time.
	ErrNonDurableSink = errors.New("audit sink is not a durable regular file")
	// ErrAuditSinkChanged is returned when the configured audit path no longer
	// references the opened audit sink inode as a non-symlink regular directory
	// entry (rotated, renamed, unlinked, replaced, atomic-renamed-over, or
	// any observed symlink, including one resolving to that inode), so an
	// append through the stale fd could not be proven durable at the path.
	ErrAuditSinkChanged = errors.New("configured audit path no longer references the opened audit sink")
	// ErrAuditSinkUnhealthy is returned when a prior write/short-write or
	// durability/binding failure has poisoned the logger until process restart.
	ErrAuditSinkUnhealthy = errors.New("audit sink is unhealthy")
)

type EventType string

const (
	EventToolAllowed          EventType = "tool_call_allowed"
	EventToolDenied           EventType = "tool_call_denied"
	EventToolApprovalRequired EventType = "tool_call_approval_required"
	EventToolChainDetected    EventType = "tool_call_chain_detected"
	EventSessionTainted       EventType = "session_tainted"
	EventSessionStarted       EventType = "session_started"
	EventSessionEnded         EventType = "session_ended"
	EventPolicyLoaded         EventType = "policy_loaded"
	EventPolicyReloaded       EventType = "policy_reloaded"
)

type Event struct {
	Timestamp              string         `json:"timestamp"`
	EventType              EventType      `json:"event_type"`
	SessionID              string         `json:"session_id"`
	AgentID                string         `json:"agent_id"`
	Server                 string         `json:"server"`
	Tool                   string         `json:"tool,omitempty"`
	Arguments              map[string]any `json:"arguments,omitempty"`
	Decision               string         `json:"policy_decision"`
	Reason                 string         `json:"reason,omitempty"`
	RiskLevel              string         `json:"risk_level,omitempty"`
	SessionTaints          []string       `json:"session_taints,omitempty"`
	TaintSource            string         `json:"taint_source,omitempty"`
	TaintReason            string         `json:"taint_reason,omitempty"`
	PolicyRule             string         `json:"policy_rule,omitempty"`
	ChainContext           []string       `json:"chain_context,omitempty"`
	RequestHash            string         `json:"request_hash,omitempty"`
	RedactedArgumentHash   string         `json:"redacted_argument_hash,omitempty"`
	PolicyHash             string         `json:"policy_hash,omitempty"`
	ChainContextHash       string         `json:"chain_context_hash,omitempty"`
	ApprovalReceiptHash    string         `json:"approval_receipt_hash,omitempty"`
	ApprovalReceipt        map[string]any `json:"approval_receipt,omitempty"`
	ServerIdentityKind     string         `json:"server_identity_kind,omitempty"`
	ServerIdentityExpected string         `json:"server_identity_expected,omitempty"`
	ServerIdentityResolved string         `json:"server_identity_resolved,omitempty"`
	ServerAttested         *bool          `json:"server_attested,omitempty"`
	ServerClaimedName      string         `json:"server_claimed_name,omitempty"`
	ServerClaimedVersion   string         `json:"server_claimed_version,omitempty"`
	ResultPreview          string         `json:"result_preview,omitempty"`
	IsError                bool           `json:"is_error,omitempty"`
	Message                string         `json:"message,omitempty"`
	Hash                   string         `json:"hash,omitempty"`
	PrevHash               string         `json:"prev_hash,omitempty"`
	ChainIndex             uint64         `json:"chain_index,omitempty"`
}

type Logger struct {
	path string
	mu   sync.Mutex
	file *os.File
	// sinkInfo is the immutable constructor identity snapshot of the opened
	// sink (file opened by NewLogger). It is nil for the stderr fallback
	// (path==""). Live path-to-fd validation at commit time compares the
	// current fd and configured path against this identity.
	sinkInfo   os.FileInfo
	patterns   []*regexp.Regexp
	prevHash   string
	chainIndex uint64
	poisoned   bool
	// write is an unexported seam for package-audit tests to inject short
	// writes. Constructors default it to (*os.File).Write.
	write func(f *os.File, data []byte) (int, error)
}

// syncDir is an unexported seam for package-audit tests to assert and inject
// the parent-directory fsync that makes a newly created audit file's
// directory entry durable. Constructors default it to (*os.File).Sync.
var syncDir = func(f *os.File) error { return f.Sync() }

// openFile is an unexported seam for package-audit tests to deterministically
// inject the rotation/creation TOCTOU window between chain recovery and the
// create-vs-existing open. Constructors default it to os.OpenFile.
var openFile = func(path string, flags int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags, perm)
}

func NewLogger(path string) (*Logger, error) {
	// Canonicalize the configured path once: reject empty and lexically
	// non-clean paths, then convert a clean relative path to an absolute
	// path. Every open, walk, and parent sync uses this stored absolute
	// path, so the binding can never drift with a later CWD change.
	abs, err := canonicalAuditPath(path)
	if err != nil {
		return nil, err
	}
	path = abs

	l := &Logger{path: path, write: (*os.File).Write}
	// Pre-open no-follow component walk: every ancestor must already exist
	// as a non-symlink directory; only the final component may be absent
	// (the create-vs-existing state machine creates it).
	if _, err := l.walkBindingLocked(false); err != nil {
		return nil, fmt.Errorf("validate audit binding: %w", err)
	}

	// Open the actual append sink FIRST, then recover or initialize the chain
	// from that exact fd. A pre-open pathname recovery can read inode A while
	// the create-vs-existing state machine later opens or creates inode B,
	// carrying A's chain state onto a fresh ledger or appending A-linked
	// metadata into B. Same-fd recovery makes stale-chain carry-over
	// impossible by construction: whichever existing inode the fallback
	// actually opens is exactly the inode whose chain is recovered and later
	// appended.
	//
	// Every open uses O_NOFOLLOW so a pre-existing symlink at the configured
	// path is rejected by the kernel instead of being followed onto an
	// unrelated victim file that would then be treated as the durable ledger.
	//
	// Detect creation atomically with the open. A pre-open Stat TOCTOU can
	// leave created=false after O_CREATE makes a new inode (parent dir never
	// synced) or created=true after opening another process's ledger (cleanup
	// would unlink it). O_EXCL is the create-vs-existing seam.
	created := false
	f, err := openFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrExist) {
		// Existing file: open append-only without O_CREATE. If the ledger
		// was rotated away between EEXIST and this open (ENOENT), retry the
		// exclusive-create path so created=true and the parent dir is synced.
		// Any other error, including a second EEXIST on retry, fails closed.
		f, err = openFile(path, os.O_RDWR|os.O_SYNC|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
		if errors.Is(err, os.ErrNotExist) {
			f, err = openFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
			if err != nil {
				return nil, fmt.Errorf("open audit log: %w", err)
			}
			created = true
		} else if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	} else {
		created = true
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat audit log: %w", err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, ErrNonDurableSink
	}

	var prevHash string
	var chainIndex uint64
	if !created {
		prevHash, chainIndex, err = recoverChainStateFromFile(f, st)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
	}

	l.file = f
	l.sinkInfo = st
	l.prevHash = prevHash
	l.chainIndex = chainIndex
	// Constructor acceptance: full post-open no-follow walk plus final
	// identity/link-count validation, then the single parent-directory sync
	// that makes the accepted binding durable, then a full post-sync
	// revalidation. This runs for both a fresh exclusive-create (the
	// filename->inode directory entry must be durable before any
	// authorization commit is permitted) and an existing inode (a retained
	// binding is re-validated and re-synced in place). On failure the fd is
	// closed and the error returned; nothing is ever pathname-unlinked,
	// because the configured pathname may now reference an inode this call
	// did not create.
	if err := l.validateDurableBindingLocked(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("validate audit binding: %w", err)
	}
	if err := syncParentDir(l.path); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync configured audit parent directory: %w", err)
	}
	if err := l.validateDurableBindingLocked(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("validate audit binding after parent sync: %w", err)
	}
	return l, nil
}

// canonicalAuditPath validates and canonicalizes the configured ledger path:
// it must be non-empty and lexically clean (path == filepath.Clean(path)),
// and it is converted once to an absolute path. Relative input is accepted
// but resolved exactly once at construction through the current working
// directory; the stored absolute path is used for every open, walk, and sync
// afterwards, so later CWD changes cannot re-resolve it.
func canonicalAuditPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("audit log path must not be empty")
	}
	if path != filepath.Clean(path) {
		return "", fmt.Errorf("audit log path must be lexically clean: %q", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve audit log path: %w", err)
	}
	return abs, nil
}

// syncParentDir makes an accepted audit binding durable by fsyncing its parent
// directory. It opens the directory read-only, syncs it, and closes it; any
// failure is returned so NewLogger can fail closed rather than permit an
// authorization commit whose audit record or binding could disappear on
// reboot. This is the single constructor-only directory sync that establishes
// the accepted binding; commit-time validation deliberately performs no fsync.
func syncParentDir(path string) error {
	parent := filepath.Dir(path)
	if parent == "" {
		parent = "."
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return syncDir(dir)
}

func MustLogger(path string) *Logger {
	if path == "" {
		return stderrLogger()
	}
	l, err := NewLogger(path)
	if err != nil {
		if errors.Is(err, ErrIncompleteAuditTail) || errors.Is(err, ErrCorruptAuditRecord) {
			log.Fatalf("audit: refusing to start with corrupt/incomplete audit log %q: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "audit logger: %v, falling back to stderr\n", err)
		return stderrLogger()
	}
	return l
}

func stderrLogger() *Logger {
	return &Logger{file: os.Stderr, write: (*os.File).Write}
}

// recoverChainStateFromFile recovers the hash-chain tip from the exact
// append sink fd that will receive future records. It never reopens the
// pathname (which could resolve to a different inode after rotation) and
// never closes the caller's fd. The caller passes the fd's current FileInfo
// so the function does not need to re-stat.
func recoverChainStateFromFile(f *os.File, st os.FileInfo) (prevHash string, chainIndex uint64, err error) {
	if st.Size() == 0 {
		return "", 0, nil
	}

	lastLine, err := readLastCompleteLine(f, st.Size())
	if err != nil {
		return "", 0, err
	}
	if len(lastLine) == 0 {
		return "", 0, nil
	}

	var last Event
	if err := json.Unmarshal(lastLine, &last); err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrCorruptAuditRecord, err)
	}
	if last.Hash == "" {
		if last.PrevHash != "" || last.ChainIndex > 0 {
			// Record carries chain metadata but hash was stripped:
			// treat as tampering, not a legacy boundary.
			return "", 0, fmt.Errorf("%w: hash stripped from chained record", ErrCorruptAuditRecord)
		}
		// Legacy record without a hash chain: treat as a chain boundary
		// so the configured audit file is preserved on upgrade.
		return "", 0, nil
	}
	// Verify integrity of recovered tip before continuing the chain.
	stored := last.Hash
	last.Hash = ""
	payload, err := json.Marshal(last)
	if err != nil {
		return "", 0, fmt.Errorf("%w: re-marshal last record: %v", ErrCorruptAuditRecord, err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != stored {
		return "", 0, fmt.Errorf("%w: last record hash mismatch", ErrCorruptAuditRecord)
	}
	return stored, last.ChainIndex + 1, nil
}

// readLastCompleteLine seeks from EOF and returns the last newline-terminated
// JSONL record without loading the full file into memory.
func readLastCompleteLine(f *os.File, size int64) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}

	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, size-1); err != nil {
		return nil, fmt.Errorf("read audit log tail: %w", err)
	}
	if buf[0] != '\n' {
		return nil, fmt.Errorf("%w", ErrIncompleteAuditTail)
	}

	const chunkSize int64 = 64 * 1024
	var (
		data      []byte
		remaining = size
	)
	for remaining > 0 {
		n := chunkSize
		if remaining < n {
			n = remaining
		}
		remaining -= n
		chunk := make([]byte, n)
		if _, err := f.ReadAt(chunk, remaining); err != nil {
			return nil, fmt.Errorf("read audit log chunk: %w", err)
		}
		data = append(chunk, data...)
		// Skip trailing whitespace-only lines. Continue reading until the tail
		// contains a non-empty record and its preceding boundary, or reach SOF.
		content := bytes.TrimRight(data, " 	\r\n")
		if remaining == 0 || (len(content) > 0 && bytes.LastIndexByte(content, '\n') >= 0) {
			break
		}
	}

	content := bytes.TrimRight(data, " 	\r\n")
	if len(content) == 0 {
		return nil, nil
	}
	if idx := bytes.LastIndexByte(content, '\n'); idx >= 0 {
		return bytes.TrimSpace(content[idx+1:]), nil
	}
	return bytes.TrimSpace(content), nil
}

func (l *Logger) SetRedactionPatterns(patterns []policy.RedactionPattern) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.patterns = l.patterns[:0]
	for _, p := range patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		l.patterns = append(l.patterns, re)
	}
}

func (l *Logger) Log(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// A poisoned logger must never append again: any write/validation/sync
	// failure means the ledger cannot be trusted, so ordinary logging fails
	// closed before candidate preparation or any write attempt.
	if l.poisoned {
		return ErrAuditSinkUnhealthy
	}

	prepared, data, err := l.prepareCandidateLocked(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit logger: marshal error: %v\n", err)
		return err
	}
	if err := l.writeRecordLocked(data); err != nil {
		fmt.Fprintf(os.Stderr, "audit logger: write error: %v\n", err)
		return err
	}
	l.prevHash = prepared.Hash
	l.chainIndex++
	return nil
}

// CommitAuthorization durably appends a terminal allow event to the hash-linked
// JSONL ledger. It accepts only EventToolAllowed with Decision "allow", requires
// a regular O_SYNC sink that has not been poisoned, and advances chain state
// only after a full write. Every commit runs the complete no-follow component
// walk (every ancestor and the final component, plus final SameFile and
// nlink==1) immediately before and immediately after the write, so any
// rotation/rebinding, observed symlink in any component, visible hard-link or
// cross-directory rebound, or durability failure before, during, or after the
// append fails closed and poisons the logger. Commit-time validation performs
// no fsync; the single parent-directory sync belongs only to the constructor's
// accepted binding. Existing O_SYNC is the write-durability boundary. Any
// observed symlink, including one resolving to the opened inode, is rejected
// without following it.
func (l *Logger) CommitAuthorization(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.EventType != EventToolAllowed || event.Decision != "allow" {
		return fmt.Errorf("authorization commit requires %s with decision allow", EventToolAllowed)
	}
	if l.poisoned {
		return ErrAuditSinkUnhealthy
	}
	// Pre-write live validation: reject a known-stale fd before any write so
	// no orphaned durable record is produced through a rotated sink.
	if err := l.validateDurableBindingLocked(); err != nil {
		return l.poisonCommitLocked(err)
	}

	prepared, data, err := l.prepareCandidateLocked(event)
	if err != nil {
		return err
	}
	if err := l.writeRecordLocked(data); err != nil {
		return err
	}
	// Post-write live validation: close the stat-to-write rotation window. If
	// the path was rebound while the O_SYNC write was in flight, the record
	// may exist in the old inode but must not authorize this call.
	if err := l.validateDurableBindingLocked(); err != nil {
		return l.poisonCommitLocked(err)
	}
	l.prevHash = prepared.Hash
	l.chainIndex++
	return nil
}

// validateDurableBindingLocked checks, under Logger.mu, that the live sink is
// still the regular constructor-bound inode and that the configured audit path
// itself is a non-symlink regular directory entry referencing that exact
// inode, with every pathname component (including every ancestor) non-symlink
// and the final entry single-link (nlink==1). Inspection is no-follow (Lstat
// on every component): any observed symlink in any component, including one
// that would resolve to the opened inode, fails closed as ErrAuditSinkChanged
// without following the target. Any missing, non-regular, renamed, unlinked,
// replaced, atomic-renamed-over, hard-linked, cross-directory-rebound, or
// different-inode condition also fails closed without writing. This
// validation performs NO fsync: runtime namespace mutation is rejected, never
// made durable; the single parent-directory sync belongs only to the
// constructor's accepted binding.
func (l *Logger) validateDurableBindingLocked() error {
	if l.path == "" || l.sinkInfo == nil || l.file == nil {
		return ErrNonDurableSink
	}
	fdInfo, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat opened sink: %v", ErrAuditSinkChanged, err)
	}
	if !fdInfo.Mode().IsRegular() {
		return ErrNonDurableSink
	}
	if !os.SameFile(l.sinkInfo, fdInfo) {
		return fmt.Errorf("%w: opened sink inode changed since construction", ErrAuditSinkChanged)
	}
	pathInfo, err := l.walkBindingLocked(true)
	if err != nil {
		return err
	}
	if !os.SameFile(fdInfo, pathInfo) {
		return fmt.Errorf("%w: configured audit path no longer references the opened sink", ErrAuditSinkChanged)
	}
	// The supported model requires a single-link regular final entry. A
	// visible second hard link (nlink>1), or a lingering fd-side nlink==0
	// after unlink, fails closed.
	if n, ok := nlinkOf(fdInfo); !ok || n != 1 {
		return fmt.Errorf("%w: opened sink link count %d (want 1)", ErrAuditSinkChanged, n)
	}
	if n, ok := nlinkOf(pathInfo); !ok || n != 1 {
		return fmt.Errorf("%w: configured audit path link count %d (want 1)", ErrAuditSinkChanged, n)
	}
	return nil
}

// walkBindingLocked walks every pathname component of the stored absolute
// configured path with no-follow Lstat, from the root down to the final
// component. Every ancestor must exist, be a non-symlink, and be a directory.
// When requireFinal is true (full walk), the final component must exist, be a
// non-symlink regular file, and its FileInfo is returned; when false
// (pre-open constructor walk) only the final component may be absent. Any
// stat/access/type uncertainty, missing ancestor, symlink in any component,
// non-directory ancestor, or non-regular final fails closed as a binding
// error.
func (l *Logger) walkBindingLocked(requireFinal bool) (os.FileInfo, error) {
	if l.path == "" {
		return nil, ErrNonDurableSink
	}
	// Split the clean absolute path into components. Every ancestor prefix is
	// walked individually so a symlinked ancestor is seen directly instead of
	// being followed by the kernel.
	clean := filepath.Clean(l.path)
	rest := strings.TrimPrefix(clean, string(os.PathSeparator))
	var comps []string
	if rest != "" {
		comps = strings.Split(rest, string(os.PathSeparator))
	}
	prefix := string(os.PathSeparator)
	for i, comp := range comps {
		prefix = filepath.Join(prefix, comp)
		fi, err := os.Lstat(prefix)
		if err != nil {
			if os.IsNotExist(err) && !requireFinal && i == len(comps)-1 {
				// Pre-open constructor walk: only the final component may
				// be absent (the create-vs-existing state machine creates
				// it); every ancestor must already exist.
				return nil, nil
			}
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w: configured audit path component %q missing", ErrAuditSinkChanged, prefix)
			}
			return nil, fmt.Errorf("%w: stat configured audit path component %q: %v", ErrAuditSinkChanged, prefix, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: configured audit path component %q is a symlink", ErrAuditSinkChanged, prefix)
		}
		if i == len(comps)-1 {
			// Final component.
			if !requireFinal {
				// Pre-open: an existing final must already be a non-symlink
				// regular entry (regularity is fully re-checked post-open).
				if !fi.Mode().IsRegular() {
					return nil, ErrNonDurableSink
				}
				return fi, nil
			}
			if !fi.Mode().IsRegular() {
				return nil, ErrNonDurableSink
			}
			return fi, nil
		}
		// Ancestor: must be a directory.
		if !fi.IsDir() {
			return nil, fmt.Errorf("%w: configured audit path ancestor %q is not a directory", ErrAuditSinkChanged, prefix)
		}
	}
	if !requireFinal {
		return nil, nil
	}
	return nil, fmt.Errorf("%w: configured audit path missing", ErrAuditSinkChanged)
}

// nlinkOf returns the link count from a FileInfo's underlying stat, or ok=false
// when the Sys() value is not the expected platform stat type (fail closed).
func nlinkOf(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}

// poisonCommitLocked marks the logger permanently unhealthy after a live
// durability/binding failure and returns the specific first failure cause.
// Every later authorization commit returns ErrAuditSinkUnhealthy without
// attempting a stat or write.
func (l *Logger) poisonCommitLocked(err error) error {
	l.poisoned = true
	return err
}

func (l *Logger) prepareCandidateLocked(event Event) (Event, []byte, error) {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if event.Arguments != nil {
		event.Arguments = l.redactMap(event.Arguments)
	}
	event.ResultPreview = l.redactString(event.ResultPreview)
	if event.Reason != "" {
		event.Reason = l.redactString(event.Reason)
	}

	event.PrevHash = l.prevHash
	event.ChainIndex = l.chainIndex

	hashData, err := l.eventHashPayload(event)
	if err != nil {
		return Event{}, nil, err
	}
	h := sha256.Sum256(hashData)
	event.Hash = hex.EncodeToString(h[:])

	data, err := json.Marshal(event)
	if err != nil {
		return Event{}, nil, err
	}
	return event, append(data, '\n'), nil
}

func (l *Logger) writeRecordLocked(data []byte) error {
	n, err := l.sinkWrite(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		l.poisoned = true
		return err
	}
	return nil
}

func (l *Logger) sinkWrite(data []byte) (int, error) {
	fn := l.write
	if fn == nil {
		fn = (*os.File).Write
	}
	return fn(l.file, data)
}

func (l *Logger) eventHashPayload(event Event) ([]byte, error) {
	e := event
	e.Hash = ""
	return json.Marshal(e)
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == os.Stderr || l.file == os.Stdout {
		return nil
	}
	return l.file.Close()
}

func (l *Logger) redactString(s string) string {
	if s == "" {
		return s
	}
	for _, re := range l.patterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

func (l *Logger) redactMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = l.redactValue(v)
	}
	return out
}

func (l *Logger) redactValue(v any) any {
	switch val := v.(type) {
	case string:
		return l.redactString(val)
	case map[string]any:
		return l.redactMap(val)
	case []any:
		redacted := make([]any, len(val))
		for i, item := range val {
			redacted[i] = l.redactValue(item)
		}
		return redacted
	default:
		return v
	}
}
