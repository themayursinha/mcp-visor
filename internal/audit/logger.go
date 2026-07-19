package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/policy"
)

var (
	// ErrIncompleteAuditTail is returned when an existing audit log ends mid-record.
	ErrIncompleteAuditTail = errors.New("audit log incomplete trailing line")
	// ErrCorruptAuditRecord is returned when the last complete audit record is invalid.
	ErrCorruptAuditRecord = errors.New("audit log corrupt last record")
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
	Timestamp            string         `json:"timestamp"`
	EventType            EventType      `json:"event_type"`
	SessionID            string         `json:"session_id"`
	AgentID              string         `json:"agent_id"`
	Server               string         `json:"server"`
	Tool                 string         `json:"tool,omitempty"`
	Arguments            map[string]any `json:"arguments,omitempty"`
	Decision             string         `json:"policy_decision"`
	Reason               string         `json:"reason,omitempty"`
	RiskLevel            string         `json:"risk_level,omitempty"`
	SessionTaints        []string       `json:"session_taints,omitempty"`
	TaintSource          string         `json:"taint_source,omitempty"`
	TaintReason          string         `json:"taint_reason,omitempty"`
	PolicyRule           string         `json:"policy_rule,omitempty"`
	ChainContext         []string       `json:"chain_context,omitempty"`
	RequestHash          string         `json:"request_hash,omitempty"`
	RedactedArgumentHash string         `json:"redacted_argument_hash,omitempty"`
	PolicyHash           string         `json:"policy_hash,omitempty"`
	ChainContextHash     string         `json:"chain_context_hash,omitempty"`
	ApprovalReceiptHash  string         `json:"approval_receipt_hash,omitempty"`
	ApprovalReceipt      map[string]any `json:"approval_receipt,omitempty"`
	ResultPreview        string         `json:"result_preview,omitempty"`
	IsError              bool           `json:"is_error,omitempty"`
	Message              string         `json:"message,omitempty"`
	Hash                 string         `json:"hash,omitempty"`
	PrevHash             string         `json:"prev_hash,omitempty"`
	ChainIndex           uint64         `json:"chain_index,omitempty"`
}

type Logger struct {
	path       string
	mu         sync.Mutex
	file       *os.File
	patterns   []*regexp.Regexp
	prevHash   string
	chainIndex uint64
}

func NewLogger(path string) (*Logger, error) {
	prevHash, chainIndex, err := recoverChainState(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{
		path:       path,
		file:       f,
		prevHash:   prevHash,
		chainIndex: chainIndex,
	}, nil
}

func MustLogger(path string) *Logger {
	if path == "" {
		return &Logger{file: os.Stderr}
	}
	l, err := NewLogger(path)
	if err != nil {
		if errors.Is(err, ErrIncompleteAuditTail) || errors.Is(err, ErrCorruptAuditRecord) {
			log.Fatalf("audit: refusing to start with corrupt/incomplete audit log %q: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "audit logger: %v, falling back to stderr\n", err)
		return &Logger{file: os.Stderr}
	}
	return l
}

func recoverChainState(path string) (prevHash string, chainIndex uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("open audit log for chain recovery: %w", err)
	}
	defer f.Close()

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

func (l *Logger) Log(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

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
	l.chainIndex++

	hashData := l.eventHashPayload(event)
	h := sha256.Sum256(hashData)
	event.Hash = hex.EncodeToString(h[:])
	l.prevHash = event.Hash

	data, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit logger: marshal error: %v\n", err)
		return
	}

	data = append(data, '\n')

	if _, err := l.file.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "audit logger: write error: %v\n", err)
	}
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
