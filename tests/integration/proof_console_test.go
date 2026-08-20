//go:build !interop

package main_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProofConsoleSnapshot(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "demo-runner")
	build := exec.Command("go", "build", "-o", bin, "../../examples/demo-runner")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build demo-runner: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "-ui", "-ui-addr", "127.0.0.1:0")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
	}()

	url, err := waitProofConsoleURL(stderr, 90*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("proof console url: %v", err)
	}

	deadline := time.Now().Add(90 * time.Second)
	var snap map[string]any
	for time.Now().Before(deadline) {
		snap, err = fetchSnapshot(url + "/api/snapshot")
		if err == nil && proofSnapshotComplete(t, snap) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !proofSnapshotComplete(t, snap) {
		t.Fatalf("proof snapshot incomplete: %#v", snap)
	}

	home, err := http.Get(url + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer home.Body.Close()
	body, err := io.ReadAll(home.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	if strings.Contains(html, "Control Plane") {
		t.Fatal("proof page must not present a control plane")
	}
	if !strings.Contains(html, "/api/snapshot") {
		t.Fatal("proof page must load live snapshot data")
	}
}

func waitProofConsoleURL(r io.Reader, timeout time.Duration) (string, error) {
	errCh := make(chan error, 1)
	urlCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := sc.Text()
			if rest, ok := strings.CutPrefix(line, "Proof Console: "); ok {
				urlCh <- strings.TrimSpace(rest)
				return
			}
		}
		if err := sc.Err(); err != nil {
			errCh <- err
			return
		}
		errCh <- io.EOF
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case url := <-urlCh:
		return url, nil
	case err := <-errCh:
		return "", err
	case <-timer.C:
		return "", os.ErrDeadlineExceeded
	}
}

func fetchSnapshot(url string) (map[string]any, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, os.ErrInvalid
	}
	var snap map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return nil, err
	}
	return snap, nil
}

func proofSnapshotComplete(t *testing.T, snap map[string]any) bool {
	t.Helper()
	events, _ := snap["audit_events"].([]any)
	obs, _ := snap["observations"].([]any)
	var sawAllow, sawTaint, sawDeny bool
	allowHashes := 0
	for _, raw := range events {
		ev, _ := raw.(map[string]any)
		switch ev["event_type"] {
		case "tool_call_allowed":
			sawAllow = true
			if ev["hash"] != nil && ev["hash"] != "" && ev["prev_hash"] != nil && ev["chain_index"] != nil {
				allowHashes++
			}
		case "session_tainted":
			sawTaint = true
		case "tool_call_denied":
			sawDeny = true
			if ev["policy_rule"] != "block_sensitive_egress" {
				return false
			}
			if ev["policy_decision"] != "deny" {
				return false
			}
		}
	}
	sawPost := false
	for _, raw := range obs {
		o, _ := raw.(map[string]any)
		tool, _ := o["tool"].(string)
		id, _ := o["request_id"].(float64)
		received, _ := o["received"].(bool)
		if tool == "http_post" && int(id) == 300 && received {
			sawPost = true
		}
	}
	return sawAllow && sawTaint && sawDeny && allowHashes >= 1 && !sawPost && len(obs) >= 2
}
