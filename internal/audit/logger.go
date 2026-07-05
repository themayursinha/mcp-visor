package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/policy"
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{
		path: path,
		file: f,
	}, nil
}

func MustLogger(path string) *Logger {
	if path == "" {
		return &Logger{file: os.Stderr}
	}
	l, err := NewLogger(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit logger: %v, falling back to stderr\n", err)
		return &Logger{file: os.Stderr}
	}
	return l
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
