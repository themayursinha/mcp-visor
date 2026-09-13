package demokit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func RepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, e := os.Stat(filepath.Join(wd, "go.mod")); e == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", errors.New("cannot find repo root (go.mod)")
		}
		wd = parent
	}
}

func Build(repoRoot, out, pkg string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = repoRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %w\n%s", pkg, err, b)
	}
	return nil
}

func Kill(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func Drain(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
	}
}

type Client struct {
	w *bufio.Writer
	r *bufio.Reader
}

func NewClient(stdin io.WriteCloser, stdout io.ReadCloser) *Client {
	return &Client{w: bufio.NewWriter(stdin), r: bufio.NewReader(stdout)}
}

func (c *Client) send(msg map[string]any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := c.w.Write(append(data, '\n')); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *Client) recv() (map[string]any, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var msg map[string]any
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *Client) Initialize(name string) error {
	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": name, "version": "1.0"},
		},
	}); err != nil {
		return err
	}
	if _, err := c.recv(); err != nil {
		return err
	}
	if err := c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return err
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}

func (c *Client) CallTool(id int, name string, args map[string]any) (map[string]any, error) {
	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	}); err != nil {
		return nil, err
	}
	return c.recv()
}

func ResponseError(resp map[string]any) (string, bool) {
	raw, ok := resp["error"]
	if !ok || raw == nil {
		return "", false
	}
	if errObj, ok := raw.(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok {
			return msg, true
		}
	}
	return fmt.Sprintf("%v", raw), true
}

func ObservedIDs(path string) ([]int, error) {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var ids []int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, fmt.Errorf("malformed observation: %w", err)
		}
		if received, _ := m["received"].(bool); received {
			if id, ok := m["request_id"].(float64); ok {
				ids = append(ids, int(id))
			}
		}
	}
	return ids, nil
}

func ContainsID(ids []int, want int) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func WaitEvent(auditPath, eventType string, timeout time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		ev, err := FindEvent(auditPath, eventType)
		if err == nil {
			return ev, nil
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("no %s event found in %s", eventType, auditPath)
	}
	return nil, last
}

func FindEvent(auditPath, eventType string) (map[string]any, error) {
	data, err := os.ReadFile(auditPath)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("malformed audit event: %w", err)
		}
		if ev["event_type"] == eventType {
			return ev, nil
		}
	}
	return nil, fmt.Errorf("no %s event found in %s", eventType, auditPath)
}

func Start(cmd *exec.Cmd) (stdin io.WriteCloser, stdout io.ReadCloser, err error) {
	stdin, err = cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	go Drain(stderr)
	return stdin, stdout, nil
}
