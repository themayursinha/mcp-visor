package main_test

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

func ksKey(t *testing.T) (string, []byte) {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, k
}
func ksDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	_ = os.Chmod(d, 0o700)
	return d
}

const ksHelper = `package main
import ("bufio"; "encoding/json"; "fmt"; "os"; "os/exec")
func main() {
	if p := os.Getenv("K_LAUNCH"); p != "" { _ = os.WriteFile(p, []byte("1"), 0600) }
	in := bufio.NewReader(os.Stdin)
	for {
		line, err := in.ReadBytes('\n')
		if err != nil { return }
		var req map[string]any
		_ = json.Unmarshal(line, &req)
		method, _ := req["method"].(string)
		id, _ := json.Marshal(req["id"])
		switch method {
		case "initialize":
			fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"h\",\"version\":\"1\"}}}\n", id)
		case "tools/call":
			params, _ := req["params"].(map[string]any)
			name, _ := params["name"].(string)
			if name == "block_write" {
				sent := os.Getenv("K_SENTINEL")
				cmd := exec.Command("sh", "-c", "sleep 8; echo hit > \""+sent+"\"")
				_ = cmd.Start()
				_, _ = cmd.Process.Wait()
			}
			fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n", id)
		default:
			if req["id"] != nil { fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n", id) }
		}
	}
}
`

func buildKSHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "h.go")
	_ = os.WriteFile(src, []byte(ksHelper), 0o600)
	bin := filepath.Join(dir, "h")
	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	return bin
}

func TestKineticStopHarness(t *testing.T) {
	visor := buildVisor(t)
	helper := buildKSHelper(t)
	t.Run("idle", func(t *testing.T) { harnessIdle(t, visor, helper) })
	t.Run("between_tool_calls", func(t *testing.T) { harnessBetween(t, visor, helper) })
	t.Run("in_flight_egress", func(t *testing.T) { harnessInflight(t, visor, helper) })
	t.Run("stale_retry", func(t *testing.T) { harnessStale(t, visor, helper) })
	t.Run("restart_reconnect", func(t *testing.T) { harnessRestart(t, visor, helper) })
	t.Run("unavailable_control_channel", func(t *testing.T) { harnessUnavail(t, visor, helper) })
}

func writeKSPolicy(t *testing.T, server string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pol.yaml")
	body := `version: "1.0"
default_action: deny
servers:
  - name: "` + server + `"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
      - name: "block_write"
        allowed: true
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func startKS(t *testing.T, visor, helper, dir, audit, sess string, epoch int, kp, launch, sent, extraTool string) (*exec.Cmd, *bufio.Writer, *bufio.Reader) {
	t.Helper()
	pol := writeKSPolicy(t, helper)
	args := []string{"serve", "-server", helper, "-policy", pol, "-audit-log", audit, "-session-id", sess, "-session-epoch", itoa(epoch), "-kill-switch-dir", dir, "-kill-switch-controller", "c1=" + kp, "-client-id", "agent"}
	cmd := exec.Command(visor, args...)
	cmd.Env = append(os.Environ(), "K_LAUNCH="+launch, "K_SENTINEL="+sent)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	w, r := bufio.NewWriter(stdin), bufio.NewReader(stdout)
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "k", "version": "1"}}})
	if _, err := readMessage(r); err != nil {
		t.Fatal(err)
	}
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	_ = extraTool
	return cmd, w, r
}
func itoa(n int) string { return strings.TrimPrefix(strings.Replace(jsonNum(n), "\"", "", -1), "") }
func jsonNum(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func stopCLI(t *testing.T, visor, dir, sess string, epoch int, kp, reason string) {
	t.Helper()
	cmd := exec.Command(visor, "stop", "--control-dir", dir, "--session-id", sess, "--revoke-through-epoch", jsonNum(epoch), "--controller-id", "c1", "--controller-key", kp, "--reason", reason, "--wait", "2s")
	out, err := cmd.CombinedOutput()
	if err != nil && cmd.ProcessState.ExitCode() != 0 && cmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("stop %v %s", err, out)
	}
}

func parseAudit(t *testing.T, path string) []audit.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var evs []audit.Event
	var prev string
	idx := uint64(0)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev audit.Event
		if json.Unmarshal([]byte(line), &ev) != nil {
			t.Fatal(line)
		}
		if err := audit.VerifyEventHash(ev); err != nil {
			t.Fatal(err)
		}
		if ev.PrevHash != prev || ev.ChainIndex != idx {
			t.Fatalf("chain %d %s", ev.ChainIndex, ev.PrevHash)
		}
		prev, idx = ev.Hash, ev.ChainIndex+1
		evs = append(evs, ev)
	}
	return evs
}
func assertNoAllowAfterStop(t *testing.T, evs []audit.Event) {
	t.Helper()
	seen := false
	for _, ev := range evs {
		if ev.EventType == audit.EventKineticStopEnforced {
			seen = true
			continue
		}
		if seen && ev.EventType == audit.EventToolAllowed {
			t.Fatal("allow after stop")
		}
	}
	if !seen {
		t.Fatal("no kinetic event")
	}
}

func harnessIdle(t *testing.T, visor, helper string) {
	dir, auditP, kp := ksDir(t), filepath.Join(t.TempDir(), "a.jsonl"), ""
	kp, _ = ksKey(t)
	cmd, _, _ := startKS(t, visor, helper, dir, auditP, "sess-idle", 1, kp, filepath.Join(t.TempDir(), "L"), filepath.Join(t.TempDir(), "S"), "")
	stopCLI(t, visor, dir, "sess-idle", 1, kp, "idle-stop")
	waitExit(t, cmd)
	evs := parseAudit(t, auditP)
	assertNoAllowAfterStop(t, evs)
}

func harnessBetween(t *testing.T, visor, helper string) {
	dir, auditP := ksDir(t), filepath.Join(t.TempDir(), "a.jsonl")
	kp, _ := ksKey(t)
	cmd, w, r := startKS(t, visor, helper, dir, auditP, "sess-bt", 1, kp, filepath.Join(t.TempDir(), "L"), filepath.Join(t.TempDir(), "S"), "")
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/x"}}})
	if _, err := readMessage(r); err != nil {
		t.Fatal(err)
	}
	stopCLI(t, visor, dir, "sess-bt", 1, kp, "between-stop")
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/y"}}})
	waitExit(t, cmd)
	assertNoAllowAfterStop(t, parseAudit(t, auditP))
}

func harnessInflight(t *testing.T, visor, helper string) {
	dir, auditP, sent := ksDir(t), filepath.Join(t.TempDir(), "a.jsonl"), filepath.Join(t.TempDir(), "sent")
	kp, _ := ksKey(t)
	cmd, w, _ := startKS(t, visor, helper, dir, auditP, "sess-if", 1, kp, filepath.Join(t.TempDir(), "L"), sent, "")
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "block_write", "arguments": map[string]any{}}})
	time.Sleep(80 * time.Millisecond)
	stopCLI(t, visor, dir, "sess-if", 1, kp, "inflight-stop")
	waitExit(t, cmd)
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(sent); err == nil {
		t.Fatal("sentinel")
	}
	assertNoAllowAfterStop(t, parseAudit(t, auditP))
}

func harnessStale(t *testing.T, visor, helper string) {
	dir, auditP := ksDir(t), filepath.Join(t.TempDir(), "a.jsonl")
	kp, _ := ksKey(t)
	cmd, w, r := startKS(t, visor, helper, dir, auditP, "sess-st", 2, kp, filepath.Join(t.TempDir(), "L"), filepath.Join(t.TempDir(), "S"), "")
	c1 := exec.Command(visor, "stop", "--control-dir", dir, "--session-id", "sess-st", "--revoke-through-epoch", "1", "--controller-id", "c1", "--controller-key", kp, "--reason", "stale", "--wait", "200ms")
	_ = c1.Run()
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/x"}}})
	if _, err := readMessage(r); err != nil {
		t.Fatal(err)
	}
	stopCLI(t, visor, dir, "sess-st", 2, kp, "real-stop")
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/y"}}})
	waitExit(t, cmd)
	assertNoAllowAfterStop(t, parseAudit(t, auditP))
}

func harnessRestart(t *testing.T, visor, helper string) {
	dir, auditP, launch := ksDir(t), filepath.Join(t.TempDir(), "a.jsonl"), filepath.Join(t.TempDir(), "L")
	kp, _ := ksKey(t)
	cmd, _, _ := startKS(t, visor, helper, dir, auditP, "sess-rs", 1, kp, launch, filepath.Join(t.TempDir(), "S"), "")
	stopCLI(t, visor, dir, "sess-rs", 1, kp, "restart-stop")
	waitExit(t, cmd)
	_ = os.Remove(launch)
	launch2 := filepath.Join(t.TempDir(), "L2")
	pol := writeKSPolicy(t, helper)
	c2 := exec.Command(visor, "serve", "-server", helper, "-policy", pol, "-audit-log", filepath.Join(t.TempDir(), "b.jsonl"), "-session-id", "sess-rs", "-session-epoch", "1", "-kill-switch-dir", dir, "-kill-switch-controller", "c1="+kp)
	c2.Env = append(os.Environ(), "K_LAUNCH="+launch2)
	out, _ := c2.CombinedOutput()
	if c2.ProcessState.ExitCode() == 0 || !strings.Contains(string(out), "kinetic stop initialization") {
		t.Fatalf("%s", out)
	}
	if _, err := os.Stat(launch2); err == nil {
		t.Fatal("relaunched")
	}
}

func harnessUnavail(t *testing.T, visor, helper string) {
	dir, auditP := ksDir(t), filepath.Join(t.TempDir(), "a.jsonl")
	kp, _ := ksKey(t)
	cmd, _, _ := startKS(t, visor, helper, dir, auditP, "sess-un", 1, kp, filepath.Join(t.TempDir(), "L"), filepath.Join(t.TempDir(), "S"), "")
	time.Sleep(50 * time.Millisecond)
	_ = os.RemoveAll(dir)
	waitExitDeadline(t, cmd, 2*time.Second)
	evs := parseAudit(t, auditP)
	found := false
	for _, ev := range evs {
		if ev.EventType == audit.EventKineticStopEnforced && ev.ResultingState == "contained_control_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing unavail event")
	}
}

func waitExit(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	waitExitDeadline(t, cmd, 3*time.Second)
}
func waitExitDeadline(t *testing.T, cmd *exec.Cmd, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		_ = cmd.Process.Kill()
		t.Fatal("visor did not exit")
	}
}
