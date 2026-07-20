package approval

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/receipt"
)

type DurableEngine struct {
	engine   *Engine
	stateDir string
	pubKey   []byte
	mu       sync.RWMutex
	pending  map[string]*durableRequest
	receipts map[string]*receipt.DecisionReceipt
}

type durableRequest struct {
	ID          string         `json:"id"`
	Tool        string         `json:"tool"`
	Server      string         `json:"server"`
	Args        map[string]any `json:"arguments"`
	Reason      string         `json:"reason"`
	RiskLevel   string         `json:"risk_level"`
	SessionID   string         `json:"session_id"`
	AgentID     string         `json:"agent_id"`
	CreatedAt   time.Time      `json:"created_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	RequestHash string         `json:"request_hash"`
}

func receiptMatchesPending(rec *receipt.DecisionReceipt, pending *durableRequest) bool {
	return rec.ExecutionID == pending.ID &&
		rec.Server == pending.Server &&
		rec.Tool == pending.Tool &&
		rec.SessionID == pending.SessionID &&
		rec.AgentID == pending.AgentID
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
		if err := de.loadState(); err != nil {
			return nil, fmt.Errorf("load durable approval state: %w", err)
		}
	}

	return de, nil
}

func (de *DurableEngine) RequestApproval(req Request) (*DurableDecision, error) {
	if req.Tool == "" || req.Server == "" || req.SessionID == "" || req.AgentID == "" {
		return nil, fmt.Errorf("approval request requires tool, server, session ID, and agent ID")
	}
	if err := validateApprovalFileID(req.ID); err != nil {
		return nil, err
	}

	rHash := hashRequest(req.Server, req.Tool, req.SessionID, req.AgentID)

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
		ID:          execID,
		Tool:        req.Tool,
		Server:      req.Server,
		Args:        req.Arguments,
		Reason:      req.Reason,
		RiskLevel:   req.RiskLevel,
		SessionID:   req.SessionID,
		AgentID:     req.AgentID,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		RequestHash: rHash,
	}

	if de.stateDir != "" {
		if err := de.persistRequest(dr); err != nil {
			return nil, fmt.Errorf("persist pending approval request: %w", err)
		}
	}
	de.mu.Lock()
	de.pending[execID] = dr
	de.mu.Unlock()

	return &DurableDecision{
		Approved:         false,
		RequiresApproval: true,
		ExecutionID:      execID,
		Request:          dr,
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
	if len(de.pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("durable receipt verification key is not configured")
	}
	if err := rec.Verify(ed25519.PublicKey(de.pubKey)); err != nil {
		return nil, fmt.Errorf("verify receipt: %w", err)
	}

	de.mu.Lock()
	defer de.mu.Unlock()

	pending, exists := de.pending[rec.ExecutionID]
	if !exists {
		rHash := hashRequest(rec.Server, rec.Tool, rec.SessionID, rec.AgentID)
		if existing, ok := de.receipts[rHash]; ok {
			return &DurableDecision{
				Approved:    existing.Decision == "approve",
				Receipt:     existing,
				ExecutionID: existing.ExecutionID,
			}, nil
		}
		return nil, fmt.Errorf("unknown execution ID: %s", rec.ExecutionID)
	}
	if !receiptMatchesPending(rec, pending) {
		return nil, fmt.Errorf("receipt does not match pending request: %s", rec.ExecutionID)
	}
	if rec.Decision != "approve" && rec.Decision != "deny" {
		return nil, fmt.Errorf("invalid receipt decision: %q", rec.Decision)
	}

	rHash := hashRequest(rec.Server, rec.Tool, rec.SessionID, rec.AgentID)
	if err := de.persistReceipt(rec); err != nil {
		return nil, fmt.Errorf("persist approval receipt: %w", err)
	}
	if err := de.removePending(rec.ExecutionID); err != nil {
		return nil, fmt.Errorf("remove completed pending approval request: %w", err)
	}
	delete(de.pending, rec.ExecutionID)
	de.receipts[rHash] = rec

	if rec.Decision == "approve" {
		return &DurableDecision{
			Approved:    true,
			Receipt:     rec,
			ExecutionID: rec.ExecutionID,
		}, nil
	}

	return &DurableDecision{
		Approved:    false,
		Reason:      fmt.Sprintf("receipt denied: %s", rec.ApprovalReason),
		Receipt:     rec,
		ExecutionID: rec.ExecutionID,
	}, nil
}

func (de *DurableEngine) GetPendingRequest(executionID string) (*durableRequest, error) {
	de.mu.Lock()
	defer de.mu.Unlock()

	dr, ok := de.pending[executionID]
	if !ok {
		return nil, fmt.Errorf("pending request not found: %s", executionID)
	}

	if time.Now().After(dr.ExpiresAt) {
		delete(de.pending, executionID)
		if err := de.removePending(executionID); err != nil {
			return nil, fmt.Errorf("remove expired pending request: %w", err)
		}
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

func (de *DurableEngine) persistRequest(dr *durableRequest) error {
	if de.stateDir == "" {
		return nil
	}
	data, err := json.MarshalIndent(dr, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pending request: %w", err)
	}
	path, err := de.stateFilePath("pending", dr.ID)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write pending request: %w", err)
	}
	return nil
}

func (de *DurableEngine) persistReceipt(rec *receipt.DecisionReceipt) error {
	if de.stateDir == "" {
		return nil
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal receipt: %w", err)
	}
	path, err := de.stateFilePath("receipt", rec.ExecutionID)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write receipt: %w", err)
	}
	return nil
}

func (de *DurableEngine) removePending(executionID string) error {
	if de.stateDir == "" {
		return nil
	}
	path, err := de.stateFilePath("pending", executionID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (de *DurableEngine) loadState() error {
	if de.stateDir == "" {
		return nil
	}
	entries, err := os.ReadDir(de.stateDir)
	if err != nil {
		return fmt.Errorf("read state directory: %w", err)
	}

	var pendingNames, receiptNames []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, "pending-"):
			if filepath.Ext(name) != ".json" {
				return fmt.Errorf("invalid durable state filename: %q", name)
			}
			pendingNames = append(pendingNames, name)
		case strings.HasPrefix(name, "receipt-"):
			if filepath.Ext(name) != ".json" {
				return fmt.Errorf("invalid durable state filename: %q", name)
			}
			receiptNames = append(receiptNames, name)
		}
	}

	completedByExec := make(map[string]*receipt.DecisionReceipt, len(receiptNames))
	// Load receipts first so a completed approval wins over a leftover pending
	// file from the persist-receipt / remove-pending crash window, independent
	// of filesystem directory order.
	for _, name := range receiptNames {
		path := filepath.Join(de.stateDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %q: %w", name, err)
		}
		rec, err := receipt.Unmarshal(data)
		if err != nil {
			return fmt.Errorf("decode receipt %q: %w", name, err)
		}
		if rec.IsExpired() {
			continue
		}
		if len(de.pubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("durable receipt verification key is not configured")
		}
		if err := rec.Verify(ed25519.PublicKey(de.pubKey)); err != nil {
			return fmt.Errorf("verify receipt %q: %w", name, err)
		}
		if rec.ExecutionID == "" || rec.Server == "" || rec.Tool == "" || rec.SessionID == "" || rec.AgentID == "" {
			return fmt.Errorf("invalid receipt %q", name)
		}
		if err := validateApprovalFileID(rec.ExecutionID); err != nil {
			return fmt.Errorf("invalid receipt %q: %w", name, err)
		}
		if rec.Decision != "approve" && rec.Decision != "deny" {
			return fmt.Errorf("invalid receipt decision in %q", name)
		}
		if name != fmt.Sprintf("receipt-%s.json", rec.ExecutionID) {
			return fmt.Errorf("receipt filename does not match execution ID: %q", name)
		}
		de.receipts[hashRequest(rec.Server, rec.Tool, rec.SessionID, rec.AgentID)] = rec
		completedByExec[rec.ExecutionID] = rec
	}

	for _, name := range pendingNames {
		path := filepath.Join(de.stateDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %q: %w", name, err)
		}
		var dr durableRequest
		if err := json.Unmarshal(data, &dr); err != nil {
			return fmt.Errorf("decode pending request %q: %w", name, err)
		}
		if dr.ID == "" || dr.Tool == "" || dr.Server == "" || dr.SessionID == "" || dr.AgentID == "" || dr.ExpiresAt.IsZero() {
			return fmt.Errorf("invalid pending request %q", name)
		}
		if err := validateApprovalFileID(dr.ID); err != nil {
			return fmt.Errorf("invalid pending request %q: %w", name, err)
		}
		if name != fmt.Sprintf("pending-%s.json", dr.ID) {
			return fmt.Errorf("pending request filename does not match ID: %q", name)
		}
		if rec, ok := completedByExec[dr.ID]; ok {
			if !receiptMatchesPending(rec, &dr) {
				return fmt.Errorf("receipt for %q does not match pending request", dr.ID)
			}
			if err := de.removePending(dr.ID); err != nil {
				return fmt.Errorf("remove completed pending request %q: %w", name, err)
			}
			continue
		}
		if time.Now().Before(dr.ExpiresAt) {
			de.pending[dr.ID] = &dr
		}
	}
	return nil
}

func (de *DurableEngine) Cleanup() {
	de.mu.Lock()
	defer de.mu.Unlock()

	now := time.Now()
	for id, dr := range de.pending {
		if now.After(dr.ExpiresAt) {
			delete(de.pending, id)
			if de.stateDir != "" {
				if path, err := de.stateFilePath("pending", id); err == nil {
					_ = os.Remove(path)
				}
			}
		}
	}
	for rHash, rec := range de.receipts {
		if rec.IsExpired() {
			delete(de.receipts, rHash)
			if de.stateDir != "" {
				if path, err := de.stateFilePath("receipt", rec.ExecutionID); err == nil {
					_ = os.Remove(path)
				}
			}
		}
	}
}

func (de *DurableEngine) Close() error {
	return nil
}

type DurableDecision struct {
	Approved         bool
	RequiresApproval bool
	Reason           string
	ExecutionID      string
	Request          *durableRequest
	Receipt          *receipt.DecisionReceipt
}

// validateApprovalFileID rejects IDs that cannot safely be used as a single
// filename component under an approval state directory.
func validateApprovalFileID(id string) error {
	if id == "" {
		return nil
	}
	if strings.ContainsRune(id, 0) {
		return fmt.Errorf("unsafe request ID: NUL bytes are not allowed")
	}
	if strings.ContainsAny(id, `/\`) || strings.ContainsRune(id, filepath.Separator) {
		return fmt.Errorf("unsafe request ID: path separators are not allowed")
	}
	if id == "." || id == ".." {
		return fmt.Errorf("unsafe request ID: %q is not allowed", id)
	}
	if filepath.Base(id) != id {
		return fmt.Errorf("unsafe request ID: must be a single path component")
	}
	return nil
}

// stateFilePath builds pending-/receipt- paths and fails closed if the ID would
// resolve outside the configured durable state directory.
func (de *DurableEngine) stateFilePath(kind, id string) (string, error) {
	if err := validateApprovalFileID(id); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s.json", kind, id)
	if filepath.Base(name) != name {
		return "", fmt.Errorf("unsafe durable state filename: %q", name)
	}
	path := filepath.Join(de.stateDir, name)
	cleanDir := filepath.Clean(de.stateDir)
	cleanPath := filepath.Clean(path)
	sep := string(os.PathSeparator)
	if cleanPath != cleanDir && !strings.HasPrefix(cleanPath, cleanDir+sep) {
		return "", fmt.Errorf("durable state path escapes state directory")
	}
	return cleanPath, nil
}

func hashRequest(server, tool, sessionID, agentID string) string {
	return fmt.Sprintf("%d:%s:%d:%s:%d:%s:%d:%s", len(server), server, len(tool), tool, len(sessionID), sessionID, len(agentID), agentID)
}
