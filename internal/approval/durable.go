package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/receipt"
)

type DurableEngine struct {
	engine    *Engine
	stateDir  string
	pubKey    []byte
	mu        sync.RWMutex
	pending   map[string]*durableRequest
	receipts  map[string]*receipt.DecisionReceipt
}

type durableRequest struct {
	ID         string    `json:"id"`
	Tool       string    `json:"tool"`
	Server     string    `json:"server"`
	Args       map[string]any `json:"arguments"`
	Reason     string    `json:"reason"`
	RiskLevel  string    `json:"risk_level"`
	SessionID  string    `json:"session_id"`
	AgentID    string    `json:"agent_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	RequestHash string   `json:"request_hash"`
}

func NewDurableEngine(engine *Engine, stateDir string, pubKey []byte) (*DurableEngine, error) {
	if stateDir != "" {
		abs, err := filepath.Abs(stateDir)
		if err != nil {
			return nil, fmt.Errorf("state dir: %w", err)
		}
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return nil, fmt.Errorf("create state dir: %w", err)
		}
		stateDir = abs
	}

	de := &DurableEngine{
		engine:   engine,
		stateDir: stateDir,
		pubKey:   pubKey,
		pending:  make(map[string]*durableRequest),
		receipts: make(map[string]*receipt.DecisionReceipt),
	}

	if stateDir != "" {
		de.loadState()
	}

	return de, nil
}

func (de *DurableEngine) RequestApproval(req Request) (*DurableDecision, error) {
	rHash := hashRequest(req.Server, req.Tool, req.SessionID)

	de.mu.RLock()
	if rec, ok := de.receipts[rHash]; ok {
		de.mu.RUnlock()
		if rec.IsExpired() {
			de.mu.Lock()
			delete(de.receipts, rHash)
			de.mu.Unlock()
		} else if rec.Decision == "approve" {
			return &DurableDecision{
				Approved:    true,
				Receipt:     rec,
				ExecutionID: rec.ExecutionID,
			}, nil
		} else {
			return &DurableDecision{
				Approved:    false,
				Reason:      fmt.Sprintf("receipt denied: %s", rec.ApprovalReason),
				ExecutionID: rec.ExecutionID,
			}, nil
		}
	} else {
		de.mu.RUnlock()
	}

	if de.engine != nil && de.engine.IsEnabled() {
		approved, err := de.engine.RequestApproval(req)
		if err != nil {
			return &DurableDecision{Approved: false, Reason: fmt.Sprintf("approval error: %v", err)}, err
		}
		if !approved {
			return &DurableDecision{Approved: false, Reason: "approval denied by operator"}, nil
		}

		rec, err := receipt.NewReceipt(
			fmt.Sprintf("exec-%d-%s", time.Now().UnixNano(), req.ID),
			req.SessionID, req.AgentID,
			req.Server, req.Tool,
			req.Reason, fmt.Sprintf("%v", req.Arguments),
			"1.0", "embedded-policy", "live-session",
			req.Reason, req.RiskLevel, "cli-approver",
			"approve", 5*time.Minute,
		)
		if err != nil {
			return &DurableDecision{Approved: true}, nil
		}

		de.mu.Lock()
		de.receipts[rHash] = rec
		de.mu.Unlock()

		return &DurableDecision{
			Approved:    true,
			Receipt:     rec,
			ExecutionID: rec.ExecutionID,
		}, nil
	}

	execID := fmt.Sprintf("exec-%d-%s", time.Now().UnixNano(), req.ID)

	dr := &durableRequest{
		ID:           execID,
		Tool:         req.Tool,
		Server:       req.Server,
		Args:         req.Arguments,
		Reason:       req.Reason,
		RiskLevel:    req.RiskLevel,
		SessionID:    req.SessionID,
		AgentID:      req.AgentID,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		RequestHash:  rHash,
	}

	de.mu.Lock()
	de.pending[execID] = dr
	de.mu.Unlock()

	if de.stateDir != "" {
		de.persistRequest(dr)
	}

	return &DurableDecision{
		Approved:     false,
		RequiresApproval: true,
		ExecutionID: execID,
		Request:     dr,
	}, nil
}

func (de *DurableEngine) SubmitReceipt(signedReceipt []byte) (*DurableDecision, error) {
	rec, err := receipt.Unmarshal(signedReceipt)
	if err != nil {
		return nil, fmt.Errorf("invalid receipt: %w", err)
	}

	if rec.IsExpired() {
		return &DurableDecision{
			Approved:    false,
			Reason:      "receipt expired",
			ExecutionID: rec.ExecutionID,
		}, fmt.Errorf("receipt expired")
	}

	de.mu.Lock()
	defer de.mu.Unlock()

	if _, exists := de.pending[rec.ExecutionID]; !exists {
		rHash := hashRequest(rec.Server, rec.Tool, rec.SessionID)
		if existing, ok := de.receipts[rHash]; ok {
			return &DurableDecision{
				Approved:    existing.Decision == "approve",
				Receipt:     existing,
				ExecutionID: existing.ExecutionID,
			}, nil
		}
		return nil, fmt.Errorf("unknown execution ID: %s", rec.ExecutionID)
	}

	delete(de.pending, rec.ExecutionID)

	rHash := hashRequest(rec.Server, rec.Tool, rec.SessionID)

	if rec.Decision == "approve" {
		de.receipts[rHash] = rec
		de.persistReceipt(rec)
		return &DurableDecision{
			Approved:    true,
			Receipt:     rec,
			ExecutionID: rec.ExecutionID,
		}, nil
	}

	de.receipts[rHash] = rec
	de.persistReceipt(rec)
	return &DurableDecision{
		Approved:    false,
		Reason:      fmt.Sprintf("receipt denied: %s", rec.ApprovalReason),
		Receipt:     rec,
		ExecutionID: rec.ExecutionID,
	}, nil
}

func (de *DurableEngine) GetPendingRequest(executionID string) (*durableRequest, error) {
	de.mu.RLock()
	defer de.mu.RUnlock()

	dr, ok := de.pending[executionID]
	if !ok {
		return nil, fmt.Errorf("pending request not found: %s", executionID)
	}

	if time.Now().After(dr.ExpiresAt) {
		delete(de.pending, executionID)
		return nil, fmt.Errorf("request expired: %s", executionID)
	}

	return dr, nil
}

func (de *DurableEngine) PendingRequests() []*durableRequest {
	de.mu.RLock()
	defer de.mu.RUnlock()

	var out []*durableRequest
	for _, dr := range de.pending {
		out = append(out, dr)
	}
	return out
}

func (de *DurableEngine) persistRequest(dr *durableRequest) {
	if de.stateDir == "" {
		return
	}
	path := filepath.Join(de.stateDir, fmt.Sprintf("pending-%s.json", dr.ID))
	data, _ := json.MarshalIndent(dr, "", "  ")
	_ = os.WriteFile(path, data, 0o600)
}

func (de *DurableEngine) persistReceipt(rec *receipt.DecisionReceipt) {
	if de.stateDir == "" {
		return
	}
	path := filepath.Join(de.stateDir, fmt.Sprintf("receipt-%s.json", rec.ExecutionID))
	data, _ := json.MarshalIndent(rec, "", "  ")
	_ = os.WriteFile(path, data, 0o600)
}

func (de *DurableEngine) loadState() {
	if de.stateDir == "" {
		return
	}
	entries, err := os.ReadDir(de.stateDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(de.stateDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		if filepath.Ext(entry.Name()) == ".json" {
			if len(entry.Name()) > 8 && entry.Name()[:8] == "pending-" {
				var dr durableRequest
				if err := json.Unmarshal(data, &dr); err != nil {
					continue
				}
				if time.Now().Before(dr.ExpiresAt) {
					de.pending[dr.ID] = &dr
				}
			} else if len(entry.Name()) > 8 && entry.Name()[:8] == "receipt-" {
				rec, err := receipt.Unmarshal(data)
				if err != nil {
					continue
				}
				rHash := hashRequest(rec.Server, rec.Tool, rec.SessionID)
				de.receipts[rHash] = rec
			}
		}
	}
}

func (de *DurableEngine) Cleanup() {
	de.mu.Lock()
	defer de.mu.Unlock()

	now := time.Now()
	for id, dr := range de.pending {
		if now.After(dr.ExpiresAt) {
			delete(de.pending, id)
			if de.stateDir != "" {
				os.Remove(filepath.Join(de.stateDir, fmt.Sprintf("pending-%s.json", id)))
			}
		}
	}
	for rHash, rec := range de.receipts {
		if rec.IsExpired() {
			delete(de.receipts, rHash)
			if de.stateDir != "" {
				os.Remove(filepath.Join(de.stateDir, fmt.Sprintf("receipt-%s.json", rec.ExecutionID)))
			}
		}
	}
}

func (de *DurableEngine) Close() error {
	return nil
}

type DurableDecision struct {
	Approved          bool
	RequiresApproval  bool
	Reason            string
	ExecutionID       string
	Request           *durableRequest
	Receipt           *receipt.DecisionReceipt
}

func hashRequest(server, tool, sessionID string) string {
	return fmt.Sprintf("%s:%s:%s", server, tool, sessionID)
}
