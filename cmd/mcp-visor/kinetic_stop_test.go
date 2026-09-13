package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/killswitch"
)

func cliDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	_ = os.Chmod(d, 0o700)
	return d
}
func cliKey(t *testing.T) (string, []byte) {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, k
}

var visorOnce sync.Once
var visorPath string

func builtVisor(t *testing.T) string {
	t.Helper()
	visorOnce.Do(func() {
		p, err := os.CreateTemp("", "mcp-visor-ks-*")
		if err != nil {
			panic(err)
		}
		_ = p.Close()
		visorPath = p.Name()
		cmd := exec.Command("go", "build", "-o", visorPath, "github.com/themayursinha/mcp-visor/cmd/mcp-visor")
		if out, err := cmd.CombinedOutput(); err != nil {
			panic(string(out) + err.Error())
		}
	})
	return visorPath
}

func TestKineticStopCLIRequiresAllAuthorityFields(t *testing.T) {
	var out, errb bytes.Buffer
	if runStop(nil, &out, &errb) != 1 {
		t.Fatal(out.String(), errb.String())
	}
}

func TestKineticStopCLIRejectsServePartialConfiguration(t *testing.T) {
	bin := builtVisor(t)
	cmd := exec.Command(bin, "serve", "--kill-switch-dir", cliDir(t), "--server", "/bin/true")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() == 0 || !strings.Contains(string(out), "kinetic stop requires") {
		t.Fatalf("%s", out)
	}
}

func TestKineticStopCLIPublishesAndObservesMatchingState(t *testing.T) {
	dir := cliDir(t)
	kp, key := cliKey(t)
	m, err := killswitch.NewMonitor(killswitch.Config{Dir: dir, SessionID: "sess-cli", SessionEpoch: 1, Controllers: map[string][]byte{"c1": key}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			raw, err := os.ReadFile(killswitch.CommandPath(dir, "sess-cli"))
			if err == nil {
				var published killswitch.Command
				if json.Unmarshal(raw, &published) == nil && published.CommandID != "" {
					_ = m.WriteState(killswitch.Stop{Command: published, RequestSHA256: strings.Repeat("cd", 32), ObservedAt: time.Now().UTC(), ResultingState: "revoked_contained"})
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	var stdout, stderr bytes.Buffer
	code := runStop([]string{"--control-dir", dir, "--session-id", "sess-cli", "--revoke-through-epoch", "2", "--controller-id", "c1", "--controller-key", kp, "--reason", "halt", "--wait", "2s"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "command_id=") || !strings.Contains(stdout.String(), "resulting_state=revoked_contained") {
		t.Fatalf("%d %s %s", code, stdout.String(), stderr.String())
	}
}

func TestKineticStopCLITimeoutReportsPublishedButUnobserved(t *testing.T) {
	dir := cliDir(t)
	kp, _ := cliKey(t)
	var stdout, stderr bytes.Buffer
	code := runStop([]string{"--control-dir", dir, "--session-id", "sess-to", "--revoke-through-epoch", "1", "--controller-id", "c1", "--controller-key", kp, "--reason", "halt", "--wait", "150ms"}, &stdout, &stderr)
	if code != 2 || strings.TrimSpace(stderr.String()) != "kinetic stop command published but enforcement was not observed before timeout" {
		t.Fatalf("%d %q %q", code, stdout.String(), stderr.String())
	}
}

func TestKineticStopCLINeverPrintsKeyOrSignature(t *testing.T) {
	dir := cliDir(t)
	kp, key := cliKey(t)
	var stdout, stderr bytes.Buffer
	_ = runStop([]string{"--control-dir", dir, "--session-id", "sess-x", "--revoke-through-epoch", "1", "--controller-id", "c1", "--controller-key", kp, "--reason", "halt", "--wait", "0"}, &stdout, &stderr)
	blob := stdout.String() + stderr.String()
	if strings.Contains(blob, hex.EncodeToString(key)) || strings.Contains(blob, `"signature"`) {
		t.Fatalf("%s", blob)
	}
}

func TestKineticStopCLIRejectsRemoteAndDemoActivation(t *testing.T) {
	bin := builtVisor(t)
	dir := cliDir(t)
	kp, _ := cliKey(t)
	cmd := exec.Command(bin, "serve", "--kill-switch-dir", dir, "--kill-switch-controller", "c1="+kp, "--session-id", "s", "--session-epoch", "1", "--audit-log", filepath.Join(t.TempDir(), "a.jsonl"), "--server-url", "http://127.0.0.1:9")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() == 0 || !strings.Contains(string(out), "not supported with --server-url") {
		t.Fatalf("%s", out)
	}
	cmd = exec.Command(bin, "serve", "--demo", "--kill-switch-dir", dir)
	out, _ = cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() == 0 || !strings.Contains(string(out), "cannot be combined") {
		t.Fatalf("%s", out)
	}
}
