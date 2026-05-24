package proxy

import (
	"encoding/json"
	"sync"
	"time"

	mcp "github.com/themayursinha/mcp-visor/internal/mcp"
)

type ToolCallRecord struct {
	Timestamp  time.Time
	ServerName string
	ToolName   string
	Arguments  map[string]any
	Result     string
}

type Session struct {
	ID        string
	ClientID  string
	CreatedAt time.Time
	ToolCalls []ToolCallRecord
	mu        sync.RWMutex
}

func NewSession(id, clientID string) *Session {
	return &Session{
		ID:        id,
		ClientID:  clientID,
		CreatedAt: time.Now(),
		ToolCalls: make([]ToolCallRecord, 0),
	}
}

func (s *Session) RecordToolCall(serverName string, req mcp.ToolsCallRequest, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ToolCalls = append(s.ToolCalls, ToolCallRecord{
		Timestamp:  time.Now(),
		ServerName: serverName,
		ToolName:   req.Name,
		Arguments:  rawToMap(req.Arguments),
		Result:     result,
	})
}

func (s *Session) RecentCalls(n int) []ToolCallRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n <= 0 || n > len(s.ToolCalls) {
		n = len(s.ToolCalls)
	}
	start := len(s.ToolCalls) - n
	result := make([]ToolCallRecord, n)
	copy(result, s.ToolCalls[start:])
	return result
}

func (s *Session) ToolCallCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ToolCalls)
}

func rawToMap(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{"_raw": string(raw)}
	}
	return m
}
