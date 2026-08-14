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
	// ErrAuditSinkUnhealthy is returned by Log and CommitAuthorization once a
	// sink has been poisoned by a failed marshal/write/sync/short-write.
	ErrAuditSinkUnhealthy = errors.New("audit sink unhealthy")
)

// syncParentDir syncs the audit file's parent directory. NewLogger calls it
// exactly once per construction so a freshly created ledger entry is durable
// before the first record. It is a package-private seam for the
// unconditional-sync test; tests that replace it must not run in parallel.
var syncParentDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

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
	path       string
	mu         sync.Mutex
	file       *os.File
	patterns   []*regexp.Regexp
	prevHash   string
	chainIndex uint64
	// durable is false for the stderr fallback so authorization commits
	// always fail closed when no trusted JSONL sink was opened.
	durable bool
	// poisoned latches after any failed marshal/write/sync/short-write;
	// Log and CommitAuthorization return ErrAuditSinkUnhealthy afterwards.
	poisoned bool
	// writeFn and syncFn are narrow seams for deterministic internal tests;
	// production construction binds them to the opened file descriptor.
	writeFn func([]byte) (int, error)
	syncFn  func() error
}

func NewLogger(path string) (*Logger, error) {
	// Open the final component with no-follow so a symlink is rejected at
	// construction. The descriptor is kept for both recovery and appends.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat audit log: %w", err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("audit log is not a regular file")
	}
	// Recover the hash chain from the SAME opened descriptor; never reopen by
	// pathname and never walk the filesystem namespace.
	prevHash, chainIndex, err := recoverChainState(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	// Unconditional one-time parent-directory sync whether the ledger is new
	// or existing. A failure here is a constructor failure: close and return.
	if err := syncParentDir(filepath.Dir(path)); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync audit directory: %w", err)
	}
	l := &Logger{
		path:       path,
		file:       f,
		prevHash:   prevHash,
		chainIndex: chainIndex,
		durable:    true,
	}
	l.writeFn = f.Write
	l.syncFn = f.Sync
	return l, nil
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
	l := &Logger{file: os.Stderr}
	l.writeFn = os.Stderr.Write
	l.syncFn = os.Stderr.Sync
	return l
}

func recoverChainState(f *os.File) (prevHash string, chainIndex uint64, err error) {
	st, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat audit log: %w", err)
	}
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
	if l.poisoned {
		return ErrAuditSinkUnhealthy
	}

	prepared, data, err := l.prepareRecord(event)
	if err != nil {
		l.poisoned = true
		return err
	}
	if err := l.appendFull(data); err != nil {
		l.poisoned = true
		return err
	}
	l.prevHash = prepared.Hash
	l.chainIndex++
	return nil
}

// CommitAuthorization durably commits the FINAL allow record before the proxy
// may relay the call. It accepts only a tool_call_allowed event with an allow
// decision on the durable JSONL sink opened by NewLogger. Under the mutex it
// prepares a hash-linked candidate without mutating chain state, performs a
// full append, explicitly syncs the file, and only then advances the in-memory
// chain. Any marshal/write/short-write/sync failure poisons the sink and
// returns an error so the caller denies the call with zero relay.
func (l *Logger) CommitAuthorization(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.poisoned {
		return ErrAuditSinkUnhealthy
	}
	if !l.durable {
		return fmt.Errorf("%w: audit sink is not durable (stderr fallback)", ErrAuditSinkUnhealthy)
	}
	if event.EventType != EventToolAllowed || event.Decision != string(policy.ActionAllow) {
		return fmt.Errorf("commit authorization: only tool_call_allowed allow events are commit-able")
	}

	prepared, data, err := l.prepareRecord(event)
	if err != nil {
		l.poisoned = true
		return err
	}
	if err := l.appendFull(data); err != nil {
		l.poisoned = true
		return err
	}
	if err := l.syncFn(); err != nil {
		l.poisoned = true
		return fmt.Errorf("audit sync: %w", err)
	}
	l.prevHash = prepared.Hash
	l.chainIndex++
	return nil
}

// prepareRecord applies timestamp/redaction and computes the hash-linked JSONL
// record for event using the CURRENT chain state WITHOUT mutating prevHash or
// chainIndex. It returns the prepared event (with Hash set) and the
// newline-terminated record bytes.
func (l *Logger) prepareRecord(event Event) (Event, []byte, error) {
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

	hashData := l.eventHashPayload(event)
	h := sha256.Sum256(hashData)
	event.Hash = hex.EncodeToString(h[:])

	data, err := json.Marshal(event)
	if err != nil {
		return Event{}, nil, fmt.Errorf("audit marshal: %w", err)
	}

	data = append(data, '\n')
	return event, data, nil
}

// appendFull performs one append and requires the full record length. A short
// write is an explicit failure so a partial record can never advance the chain
// or be followed by an authorization commit.
func (l *Logger) appendFull(data []byte) error {
	n, err := l.writeFn(data)
	if err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (l *Logger) eventHashPayload(event Event) []byte {
	e := event
	e.Hash = ""
	data, _ := json.Marshal(e)
	return data
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
