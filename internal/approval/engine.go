package approval

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	mu      sync.RWMutex
	dir     string
	timeout time.Duration
	cli     bool
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

func NewCLIEngine(timeout time.Duration) *Engine {
	return &Engine{cli: true, timeout: timeout}
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
	return e.dir != "" || e.cli
}

// SetTimeout updates the approval wait timeout for subsequent requests.
// Safe for concurrent use with RequestApproval (hot policy reload).
func (e *Engine) SetTimeout(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.timeout = d
}

// Timeout returns the current approval wait timeout.
func (e *Engine) Timeout() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.timeout
}

func (e *Engine) RequestApproval(req Request) (bool, error) {
	return e.RequestApprovalWithTimeout(req, e.Timeout())
}

// RequestApprovalWithTimeout waits using a timeout captured by the caller.
// It lets a policy decision pin its approval semantics across a later reload.
func (e *Engine) RequestApprovalWithTimeout(req Request, timeout time.Duration) (bool, error) {
	if e.cli {
		return e.requestCLIApprovalWithTimeout(req, timeout)
	}

	if !e.IsEnabled() {
		return false, fmt.Errorf("approval backend is not configured")
	}

	if err := e.writeRequest(req); err != nil {
		return false, fmt.Errorf("write approval request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return e.waitForDecision(ctx, req.ID, timeout)
}

func (e *Engine) requestCLIApproval(req Request) (bool, error) {
	return e.requestCLIApprovalWithTimeout(req, e.Timeout())
}

func (e *Engine) requestCLIApprovalWithTimeout(req Request, timeout time.Duration) (bool, error) {
	fmt.Fprintf(os.Stderr, "\n========================================\n")
	fmt.Fprintf(os.Stderr, " APPROVAL REQUIRED\n")
	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, " Tool:      %s\n", req.Tool)
	fmt.Fprintf(os.Stderr, " Server:    %s\n", req.Server)
	fmt.Fprintf(os.Stderr, " Risk:      %s\n", req.RiskLevel)
	fmt.Fprintf(os.Stderr, " Reason:    %s\n", req.Reason)
	fmt.Fprintf(os.Stderr, " Agent:     %s\n", req.AgentID)
	fmt.Fprintf(os.Stderr, " Session:   %s\n", req.SessionID)
	if len(req.Arguments) > 0 {
		fmt.Fprintf(os.Stderr, " Arguments:\n")
		for k, v := range req.Arguments {
			fmt.Fprintf(os.Stderr, "   %s: %v\n", k, v)
		}
	}
	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, " Timeout in %v. Type 'yes' to approve, anything else to deny.\n", timeout)
	fmt.Fprintf(os.Stderr, "> ")

	done := make(chan bool, 1)
	errCh := make(chan error, 1)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			errCh <- err
			return
		}
		done <- strings.TrimSpace(strings.ToLower(input)) == "yes"
	}()

	select {
	case <-time.After(timeout):
		fmt.Fprintf(os.Stderr, "\nApproval timed out. Denied.\n")
		return false, fmt.Errorf("approval timed out after %v", timeout)
	case err := <-errCh:
		return false, fmt.Errorf("read input: %w", err)
	case approved := <-done:
		if approved {
			fmt.Fprintf(os.Stderr, "Approved.\n")
		} else {
			fmt.Fprintf(os.Stderr, "Denied.\n")
		}
		return approved, nil
	}
}

func (e *Engine) writeRequest(req Request) error {
	reqPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.json", req.ID))
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(reqPath, data, 0o600)
}

func (e *Engine) waitForDecision(ctx context.Context, id string, timeout time.Duration) (bool, error) {
	okPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.ok", id))
	noPath := filepath.Join(e.dir, fmt.Sprintf("req-%s.no", id))

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.cleanup(id)
			return false, fmt.Errorf("approval timed out after %v", timeout)
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
