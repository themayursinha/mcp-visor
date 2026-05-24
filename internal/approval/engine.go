package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Request struct {
	ID        string         `json:"id"`
	Tool      string         `json:"tool"`
	Server    string         `json:"server"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Reason    string         `json:"reason"`
	RiskLevel string         `json:"risk_level"`
	SessionID string         `json:"session_id"`
	AgentID   string         `json:"agent_id"`
}

type Engine struct {
	dir     string
	timeout time.Duration
}

func NewEngine(dir string, timeout time.Duration) (*Engine, error) {
	if dir == "" {
		return &Engine{dir: "", timeout: timeout}, nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("approval dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create approval dir: %w", err)
	}
	return &Engine{dir: abs, timeout: timeout}, nil
}

func MustEngine(dir string, timeout time.Duration) *Engine {
	eng, err := NewEngine(dir, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "approval engine: %v\n", err)
		return &Engine{dir: "", timeout: timeout}
	}
	return eng
}

func (e *Engine) IsEnabled() bool {
	return e.dir != ""
}

func (e *Engine) RequestApproval(req Request) (bool, error) {
	if !e.IsEnabled() {
		return true, nil
	}

	if err := e.writeRequest(req); err != nil {
		return false, fmt.Errorf("write approval request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	return e.waitForDecision(ctx, req.ID)
}

func (e *Engine) writeRequest(req Request) error {
	reqPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.json", req.ID))
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(reqPath, data, 0o600)
}

func (e *Engine) waitForDecision(ctx context.Context, id string) (bool, error) {
	okPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.ok", id))
	noPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.no", id))

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.cleanup(id)
			return false, fmt.Errorf("approval timed out after %v", e.timeout)
		case <-ticker.C:
			if _, err := os.Stat(okPath); err == nil {
				e.cleanup(id)
				return true, nil
			}
			if _, err := os.Stat(noPath); err == nil {
				e.cleanup(id)
				return false, nil
			}
		}
	}
}

func (e *Engine) cleanup(id string) {
	reqPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.json", id))
	okPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.ok", id))
	noPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.no", id))

	os.Remove(reqPath)
	os.Remove(okPath)
	os.Remove(noPath)
}
