package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/killswitch"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func kkey(t *testing.T) (string, []byte) {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, k
}
func kdir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	_ = os.Chmod(d, 0o700)
	return d
}
func kpol(t *testing.T, server, tool string, approval bool) *policy.Policy {
	t.Helper()
	extra := ""
	if approval {
		extra = "        approval_required: true\n"
	}
	return mustLoadPolicy(t, `version: "1.0"
default_action: deny
servers:
  - name: "`+server+`"
    allowed: true
    tools:
      - name: "`+tool+`"
        allowed: true
`+extra)
}
func ksign(t *testing.T, key []byte, sess string, epoch uint64, id, reason string) killswitch.Command {
	t.Helper()
	c := killswitch.Command{SchemaVersion: 1, CommandID: strings.Repeat("ab", 16), SessionID: sess, RevokeThroughEpoch: epoch, ControllerID: id, Reason: reason}
	if err := killswitch.SignCommand(&c, key); err != nil {
		t.Fatal(err)
	}
	return c
}

const kHelperSrc = `package main
import ("bufio"; "encoding/json"; "fmt"; "os"; "os/exec"; "syscall")
func main() {
	if p := os.Getenv("K_LAUNCH"); p != "" { _ = os.WriteFile(p, []byte("launched"), 0600) }
	if p := os.Getenv("K_PGID"); p != "" { pgid, _ := syscall.Getpgid(os.Getpid()); _ = os.WriteFile(p, []byte(fmt.Sprintf("%d %d", os.Getpid(), pgid)), 0600) }
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

func buildKHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "h.go")
	if err := os.WriteFile(src, []byte(kHelperSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "h")
	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	return bin
}

func TestKineticStopRedContract(t *testing.T) {
	helper := buildKHelper(t)
	t.Run("default_off", func(t *testing.T) {
		trap := filepath.Join(t.TempDir(), "nope")
		p := New(Config{ServerCommand: helper, ServerName: "h", SessionID: "s", Policy: kpol(t, "h", "file_read", false)})
		if p.kineticEnabled() {
			t.Fatal("enabled")
		}
		if rev, _ := p.kineticGate(); rev {
			t.Fatal("gate")
		}
		if _, err := os.Lstat(trap); !os.IsNotExist(err) && p.kineticMon != nil {
			t.Fatal("control read")
		}
	})
	t.Run("init_rejects", func(t *testing.T) {
		dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
		_, key := kkey(t)
		ctrls := []killswitch.ControllerKey{{ID: "c1", Key: key}}
		cases := []Config{
			{KillSwitchDir: dir, KillSwitchControllers: ctrls, SessionEpoch: 1, ServerURL: "http://127.0.0.1:1", SessionID: "s", AuditLogPath: audit},
			{KillSwitchDir: dir, KillSwitchControllers: ctrls, SessionEpoch: 1, AuditLogPath: audit},
			{KillSwitchDir: dir, KillSwitchControllers: ctrls, SessionEpoch: 0, SessionID: "s", AuditLogPath: audit},
			{KillSwitchDir: dir, SessionEpoch: 1, SessionID: "s", AuditLogPath: audit},
			{KillSwitchDir: dir, KillSwitchControllers: ctrls, SessionEpoch: 1, SessionID: "s"},
		}
		for i, cfg := range cases {
			cfg.ServerCommand, cfg.ServerName, cfg.Policy = helper, "h", kpol(t, "h", "file_read", false)
			p := New(cfg)
			if p.kineticInitErr == nil {
				t.Fatalf("case %d", i)
			}
		}
	})
	t.Run("gate_first", func(t *testing.T) {
		dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
		_, key := kkey(t)
		p := New(Config{ServerName: "h", SessionID: "sess-g", SessionEpoch: 1, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, "h", "file_read", false)})
		p.kineticRevoked.Store(true)
		out := &bytes.Buffer{}
		_, action := p.interceptAndModify(toolCallRaw(1, "file_read", map[string]any{"path": "/x"}), mcp.NewParser(nil, out))
		if action != "denied" || !strings.Contains(out.String(), "kinetic stop: session sess-g epoch 1 is revoked") {
			t.Fatalf("%s %s", action, out)
		}
	})
	t.Run("approval_recheck", func(t *testing.T) {
		dir, adir, audit := kdir(t), t.TempDir(), filepath.Join(t.TempDir(), "a.jsonl")
		_, key := kkey(t)
		p := New(Config{ServerName: "h", SessionID: "sess-a", SessionEpoch: 1, AuditLogPath: audit, ApprovalDir: adir, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, "h", "slack_send_message", true)})
		go func() {
			for {
				matches, _ := filepath.Glob(filepath.Join(adir, "req-*.json"))
				if len(matches) > 0 {
					p.kineticRevoked.Store(true)
					base := strings.TrimSuffix(filepath.Base(matches[0]), ".json")
					_ = os.WriteFile(filepath.Join(adir, base+".ok"), nil, 0o600)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		out := &bytes.Buffer{}
		_, action := p.interceptAndModify(toolCallRaw(1, "slack_send_message", map[string]any{"text": "x"}), mcp.NewParser(nil, out))
		if action != "denied" || !strings.Contains(out.String(), "kinetic stop: session sess-a epoch 1 is revoked") {
			t.Fatalf("%s %s", action, out)
		}
	})
	t.Run("inflight_and_idle_and_between", func(t *testing.T) {
		testKineticLive(t, helper)
	})
	t.Run("stale_higher_restart_unavailable_oneshot_race", func(t *testing.T) {
		testKineticLifecycle(t, helper)
	})
}

func testKineticLive(t *testing.T, helper string) {
	dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
	_, key := kkey(t)
	sent := filepath.Join(t.TempDir(), "sent")
	launch := filepath.Join(t.TempDir(), "launch")
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	// The stdin write end must stay reachable for the whole test. An unreachable
	// *os.File is closed by its finalizer when the GC runs, which makes the proxy
	// observe EOF on its client stream ("read from client: read: EOF") before the
	// kinetic stop is enforced. Closing it here keeps it live and releases the fd.
	defer func() { _ = inW.Close() }()
	p := New(Config{ServerCommand: helper, ServerName: helper, ServerArgs: nil, SessionID: "sess-live", SessionEpoch: 1, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, helper, "block_write", false)})
	p.cfg.ServerArgs = nil
	os.Setenv("K_SENTINEL", sent)
	os.Setenv("K_LAUNCH", launch)
	defer os.Unsetenv("K_SENTINEL")
	defer os.Unsetenv("K_LAUNCH")
	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { errCh <- p.Run(ctx) }()
	clientBuf := &bytes.Buffer{}
	go func() { _, _ = io.Copy(clientBuf, outR) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(launch); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, _ = inW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n"))
	time.Sleep(200 * time.Millisecond)
	_, _ = inW.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))
	time.Sleep(100 * time.Millisecond)
	_, _ = inW.Write([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"block_write","arguments":{}}}` + "\n"))
	time.Sleep(150 * time.Millisecond)
	c := ksign(t, key, "sess-live", 1, "c1", "halt-in-flight")
	if _, err := killswitch.WriteCommand(dir, c); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "kinetic stop enforced") {
			t.Fatalf("run %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout stop")
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(sent); err == nil {
		t.Fatal("sentinel")
	}
}

func testKineticLifecycle(t *testing.T, helper string) {
	dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
	_, key := kkey(t)
	launch := filepath.Join(t.TempDir(), "launch")
	p := New(Config{ServerCommand: helper, ServerName: helper, SessionID: "sess-lc", SessionEpoch: 5, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, helper, "file_read", false)})
	stale := ksign(t, key, "sess-lc", 1, "c1", "stale")
	if _, err := killswitch.WriteCommand(dir, stale); err != nil {
		t.Fatal(err)
	}
	if err := p.kineticMon.StartupCheck(); err != nil {
		t.Fatal(err)
	}
	hi := ksign(t, key, "sess-lc", 5, "c1", "now")
	if _, err := killswitch.WriteCommand(dir, hi); err != nil {
		t.Fatal(err)
	}
	p.kineticStopOnce.Do(func() {})
	p.kineticStopOnce = sync.Once{}
	p.enforceKineticStop(killswitch.Stop{Command: hi, RequestSHA256: strings.Repeat("aa", 32), ObservedAt: time.Now().UTC(), ResultingState: "revoked_contained"})
	p.enforceKineticStop(killswitch.Stop{Command: hi, ResultingState: "revoked_contained"})
	if !p.kineticRevoked.Load() {
		t.Fatal("latch")
	}
	out := &bytes.Buffer{}
	_, action := p.interceptAndModify(toolCallRaw(3, "file_read", map[string]any{"path": "/x"}), mcp.NewParser(nil, out))
	if action != "denied" {
		t.Fatal(action)
	}
	os.Setenv("K_LAUNCH", launch)
	defer os.Unsetenv("K_LAUNCH")
	p2 := New(Config{ServerCommand: helper, ServerName: helper, SessionID: "sess-lc", SessionEpoch: 5, AuditLogPath: filepath.Join(t.TempDir(), "b.jsonl"), KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, helper, "file_read", false)})
	if err := p2.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "kinetic stop initialization") {
		t.Fatalf("restart %v", err)
	}
	if _, err := os.Stat(launch); err == nil {
		t.Fatal("helper launched")
	}
	p3 := New(Config{ServerCommand: helper, ServerName: helper, SessionID: "sess-lc", SessionEpoch: 6, AuditLogPath: filepath.Join(t.TempDir(), "c.jsonl"), KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, helper, "file_read", false)})
	if p3.kineticInitErr != nil {
		t.Fatal(p3.kineticInitErr)
	}
	if err := p3.kineticMon.StartupCheck(); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var got string
	_ = p3.kineticMon.Run(ctx, func(s killswitch.Stop) { got = s.ResultingState })
	if got != "contained_control_unavailable" {
		t.Fatalf("unavail %q", got)
	}
}

func TestKineticStopLatchesWithoutRuntimeLock(t *testing.T) {
	dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
	_, key := kkey(t)
	p := New(Config{ServerName: "h", SessionID: "sess-latch", SessionEpoch: 1, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, "h", "file_read", false)})
	p.runtimeMu.RLock()
	defer p.runtimeMu.RUnlock()
	go p.enforceKineticStop(killswitch.Stop{Command: ksign(t, key, "sess-latch", 1, "c1", "latch"), RequestSHA256: strings.Repeat("aa", 32), ObservedAt: time.Now().UTC(), ResultingState: "revoked_contained"})
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if p.kineticRevoked.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !p.kineticRevoked.Load() {
		t.Fatal("latch blocked on runtimeMu")
	}
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(audit)
		if bytes.Contains(b, []byte("kinetic_stop_enforced")) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	b, _ := os.ReadFile(audit)
	if !bytes.Contains(b, []byte("kinetic_stop_enforced")) {
		t.Fatal("persist blocked on runtimeMu")
	}
	done := make(chan struct{})
	go func() {
		p.kineticPersistWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(400 * time.Millisecond):
		t.Fatal("waited persist completion blocked on runtimeMu")
	}
}

func TestKineticEncodeRefusedAfterRevoke(t *testing.T) {
	dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
	_, key := kkey(t)
	p := New(Config{ServerName: "h", SessionID: "sess-enc", SessionEpoch: 1, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, "h", "file_read", false)})
	p.kineticRevoked.Store(true)
	if err := p.encodeIfNotRevoked(func(json.RawMessage) error { t.Fatal("encoded"); return nil }, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "encode refused") {
		t.Fatalf("got %v", err)
	}
}

func TestKineticEncodeHoldsIOMutexAcrossWrite(t *testing.T) {
	dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
	_, key := kkey(t)
	p := New(Config{ServerName: "h", SessionID: "sess-enc-io", SessionEpoch: 1, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, "h", "file_read", false)})
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- p.encodeIfNotRevoked(func(json.RawMessage) error {
			close(started)
			<-release
			return nil
		}, []byte(`{}`))
	}()
	<-started
	p.kineticRevoked.Store(true)
	var raced atomic.Bool
	second := make(chan error, 1)
	go func() {
		second <- p.encodeIfNotRevoked(func(json.RawMessage) error {
			raced.Store(true)
			return nil
		}, []byte(`{}`))
	}()
	select {
	case err := <-second:
		t.Fatalf("second encode returned before first write finished: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first %v", err)
	}
	err := <-second
	if raced.Load() || err == nil || !strings.Contains(err.Error(), "encode refused") {
		t.Fatalf("raced=%v err=%v", raced.Load(), err)
	}
}

func TestKineticLaunchRefusedAfterRevoke(t *testing.T) {
	dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
	_, key := kkey(t)
	p := New(Config{ServerName: "h", SessionID: "sess-ln", SessionEpoch: 1, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, "h", "file_read", false)})
	p.kineticRevoked.Store(true)
	cmd := exec.Command("true")
	if err := p.startSupervised(cmd, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "refused launch") {
		t.Fatalf("got %v", err)
	}
	if cmd.Process != nil {
		t.Fatal("started")
	}
}

func TestKineticLaunchWaitsForIOMutexThenRefuses(t *testing.T) {
	dir, audit := kdir(t), filepath.Join(t.TempDir(), "a.jsonl")
	_, key := kkey(t)
	p := New(Config{ServerName: "h", SessionID: "sess-ln-io", SessionEpoch: 1, AuditLogPath: audit, KillSwitchDir: dir, KillSwitchControllers: []killswitch.ControllerKey{{ID: "c1", Key: key}}, Policy: kpol(t, "h", "file_read", false)})
	p.kineticIOMu.Lock()
	p.kineticRevoked.Store(true)
	cmd := exec.Command("true")
	done := make(chan error, 1)
	go func() { done <- p.startSupervised(cmd, nil, nil, nil) }()
	select {
	case err := <-done:
		t.Fatalf("launch returned while IO lock held: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	p.kineticIOMu.Unlock()
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "refused launch") || cmd.Process != nil {
		t.Fatalf("got %v proc %v", err, cmd.Process)
	}
}
