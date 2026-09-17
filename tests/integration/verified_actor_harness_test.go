package main_test

// H52 — the identity-aware path must be provable at the backend, not inside the
// decision path.
//
// H50 proves that Visor returns a denial at the intercept gate. It does not prove
// that the MCP server never received the call, and its own text says so. A denial
// returned to the client for a call that had already been relayed would satisfy
// every H50 test and still be a complete failure of the property the project
// claims. This harness closes that gap with an independent backend observer:
//
//	server_received(action) IMPLIES verified_actor(action) AND policy_allowed(action) AND durable_allow(action)
//
// The observer is a separate MCP server process that records every tools/call it
// receives on the wire. It imports nothing from mcp-visor and never reads Visor's
// audit ledger, so "the backend did not receive it" cannot be an artifact of Visor
// reporting its own success. It writes its artifact to a temp directory outside the
// repository: harness/identity-aware.sh points H52_ARTIFACT_DIR at the
// snapshot-excluded evidence/harness tree, and a bare `go test` keeps it in a
// temp directory.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/actorcontext"
)

// h52ObserverSource is the independent backend observer. Standard library only:
// its single input is the bytes it receives on stdin.
const h52ObserverSource = `package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	f, err := os.OpenFile(os.Getenv("OBSERVER_LOG"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "observer: open log:", err)
		os.Exit(2)
	}
	defer f.Close()
	in := bufio.NewReader(os.Stdin)
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			return
		}
		var req map[string]any
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"observer-backend\",\"version\":\"1\"}}}\n", rawID(req["id"]))
		case "tools/call":
			params, _ := req["params"].(map[string]any)
			tool, _ := params["name"].(string)
			encoded, _ := json.Marshal(params["arguments"])
			sum := sha256.Sum256(encoded)
			rec, _ := json.Marshal(map[string]any{
				"received_at": time.Now().UTC().Format(time.RFC3339Nano),
				"transaction": req["id"],
				"method":      method,
				"tool":        tool,
				"args_sha256": hex.EncodeToString(sum[:]),
			})
			_, _ = f.Write(append(rec, '\n'))
			_ = f.Sync()
			fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"observed\"}]}}\n", rawID(req["id"]))
		default:
			if req["id"] != nil {
				fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n", rawID(req["id"]))
			}
		}
	}
}

func rawID(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}
`

// h52Policy* are the three reference configurations. %s is the backend path,
// which is also the server name the proxy matches policy against.
const (
	h52PolicyIdentityRequired = `version: "1.0"
description: "H52: process-start identity required, scopes enforced"
default_action: deny
settings:
  require_verified_actor: true
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
        required_scopes: ["write"]
      - name: "read_file"
        allowed: true
        risk: low
        required_scopes: ["read"]
`

	h52PolicyScopeGateOnly = `version: "1.0"
description: "H52: call-time gate only (required_scopes), no process-start requirement"
default_action: deny
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
        required_scopes: ["write"]
`

	h52PolicyNoIdentity = `version: "1.0"
description: "H52 discriminating control: same tool, no identity requirement"
default_action: deny
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
`

	h52PolicyApprovalRequired = `version: "1.0"
description: "H52: approval required, actor expiry rechecked on a fresh clock"
default_action: deny
settings:
  require_verified_actor: true
  approval_timeout_seconds: 10
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
        approval_required: true
        required_scopes: ["write"]
`
)

type h52ObserverLine struct {
	ReceivedAt  string          `json:"received_at"`
	Transaction json.RawMessage `json:"transaction"`
	Method      string          `json:"method"`
	Tool        string          `json:"tool"`
	ArgsSHA256  string          `json:"args_sha256"`
}

type h52HarnessResult struct {
	name             string
	response         string
	stderr           string
	exited           bool
	exitCode         int
	observer         []h52ObserverLine
	observerArtifact string
	audit            []map[string]any
	callSent         bool
}

// buildH52Observer compiles the independent backend observer.
func buildH52Observer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "observer.go")
	if err := os.WriteFile(src, []byte(h52ObserverSource), 0o600); err != nil {
		t.Fatalf("write observer source: %v", err)
	}
	bin := filepath.Join(dir, "observer-backend")
	build := exec.Command("go", "build", "-o", bin, src)
	build.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build observer backend: %v\n%s", err, out)
	}
	return bin
}

// h52Actor seals a structurally valid VerifiedActorContext.
func h52Actor(t *testing.T, mutate func(*actorcontext.Context)) []byte {
	t.Helper()
	c := h52ActorBase(t, mutate)
	if err := c.Seal(); err != nil {
		t.Fatalf("seal actor context: %v", err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal actor context: %v", err)
	}
	return raw
}

// h52UnsealedActor returns a payload that is deliberately not sealed, for the
// scenarios where the context must fail structural validation before serving.
func h52UnsealedActor(t *testing.T, mutate func(*actorcontext.Context)) []byte {
	t.Helper()
	raw, err := json.Marshal(h52ActorBase(t, mutate))
	if err != nil {
		t.Fatalf("marshal actor context: %v", err)
	}
	return raw
}

func h52ActorBase(t *testing.T, mutate func(*actorcontext.Context)) *actorcontext.Context {
	t.Helper()
	c := &actorcontext.Context{
		Version:            actorcontext.VersionV1,
		PrincipalID:        "user1",
		ActingAgent:        "coding-agent",
		Transaction:        "txn-h52",
		ActorChain:         []actorcontext.ActorRef{{ID: "user1"}, {ID: "planner"}, {ID: "coding-agent"}},
		Scopes:             []string{"read", "write"},
		Issuer:             "https://sts.example.test",
		Audience:           "https://visor-gateway.example.test",
		TokenID:            "jti-h52",
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
		ProofKeyThumbprint: "thumb",
		VerificationMethod: actorcontext.VerificationSTSDpop,
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

type h52Options struct {
	name          string
	policy        string
	actor         []byte
	arguments     map[string]any
	approvalDelay time.Duration
}

// runIdentityHarness starts one visor serve process against the observer backend,
// drives one tools/call, and returns everything the artifacts say. Assertions live
// in the callers; this function only measures.
func runIdentityHarness(t *testing.T, visor, backend string, opts h52Options) h52HarnessResult {
	t.Helper()
	res := h52HarnessResult{name: opts.name}
	dir := t.TempDir()
	observerLog := h52ObserverPath(t, opts.name)
	res.observerArtifact = observerLog
	auditLog := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(fmt.Sprintf(opts.policy, backend)), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	session := "sess-h52-" + opts.name
	args := []string{"serve", "-server", backend, "-policy", policyPath, "-audit-log", auditLog,
		"-session-id", session, "-client-id", "h52-client"}
	var extraFiles []*os.File
	if opts.actor != nil {
		actorPath := filepath.Join(dir, "actor.json")
		if err := os.WriteFile(actorPath, opts.actor, 0o600); err != nil {
			t.Fatalf("write actor payload: %v", err)
		}
		f, err := os.Open(actorPath)
		if err != nil {
			t.Fatalf("open actor payload: %v", err)
		}
		t.Cleanup(func() { _ = f.Close() })
		// fd 3 is the process-start channel the proxy reads the context from.
		extraFiles = append(extraFiles, f)
		args = append(args, "-verified-actor-fd", "3")
	}
	approvalDir := ""
	if opts.approvalDelay > 0 {
		approvalDir = filepath.Join(dir, "approvals")
		if err := os.MkdirAll(approvalDir, 0o700); err != nil {
			t.Fatalf("create approval dir: %v", err)
		}
		args = append(args, "-approval-dir", approvalDir)
	}

	cmd := exec.Command(visor, args...)
	cmd.Env = append(os.Environ(), "OBSERVER_LOG="+observerLog)
	cmd.ExtraFiles = extraFiles
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	callID := "txn-" + opts.name
	finish := func() h52HarnessResult {
		if !res.exited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		res.stderr = stderrBuf.String()
		res.observer = h52ReadObserver(t, observerLog)
		res.audit = h52ReadAudit(t, auditLog)
		return res
	}

	initMsg := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "h52-harness", "version": "1.0.0"}},
	}
	if err := h52Send(w, initMsg); err != nil {
		t.Fatalf("send initialize: %v", err)
	}
	line, ok := h52ReadLine(t, r, 20*time.Second)
	if !ok {
		// The proxy refused to start (for example: identity required and no
		// process-start context). Measure the refusal; the caller asserts it.
		waitErr := cmd.Wait()
		res.exited = true
		res.exitCode = h52ExitCode(waitErr)
		return finish()
	}
	res.response = line

	_ = h52Send(w, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	call := map[string]any{
		"jsonrpc": "2.0", "id": callID, "method": "tools/call",
		"params": map[string]any{"name": "write_file", "arguments": opts.arguments},
	}
	callAt := time.Now()
	if err := h52Send(w, call); err != nil {
		t.Fatalf("send tools/call: %v", err)
	}
	res.callSent = true

	if opts.approvalDelay > 0 {
		id := h52WaitApprovalRequest(t, approvalDir, 15*time.Second)
		if remain := opts.approvalDelay - time.Since(callAt); remain > 0 {
			time.Sleep(remain)
		}
		_ = os.WriteFile(filepath.Join(approvalDir, "req-"+id+".ok"), []byte{}, 0o600)
	}

	if line, ok := h52ReadLine(t, r, 30*time.Second); ok {
		res.response = line
	} else {
		res.exited = true
	}
	return finish()
}

// h52ObserverPath returns where the independent observer records this scenario.
// A verification command must not change the repository snapshot digest, so the
// artifact goes to a temp directory unless the harness entry point sets
// H52_ARTIFACT_DIR, which points at the digest-excluded evidence/harness tree.
func h52ObserverPath(t *testing.T, scenario string) string {
	t.Helper()
	if dir := strings.TrimSpace(os.Getenv("H52_ARTIFACT_DIR")); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create H52_ARTIFACT_DIR: %v", err)
		}
		return filepath.Join(dir, scenario+".jsonl")
	}
	return filepath.Join(t.TempDir(), "backend-received.jsonl")
}

func h52ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func h52SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func h52Send(w *bufio.Writer, msg map[string]any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return w.Flush()
}

func h52ReadLine(t *testing.T, r *bufio.Reader, timeout time.Duration) (string, bool) {
	t.Helper()
	type readResult struct {
		line string
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- readResult{line: line, err: err}
	}()
	select {
	case got := <-ch:
		if got.err != nil {
			return "", false
		}
		return strings.TrimSpace(got.line), true
	case <-time.After(timeout):
		return "", false
	}
}

func h52WaitApprovalRequest(t *testing.T, dir string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, "req-") && strings.HasSuffix(name, ".json") {
					return strings.TrimSuffix(strings.TrimPrefix(name, "req-"), ".json")
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no approval request appeared in %s within %s", dir, timeout)
	return ""
}

func h52ReadObserver(t *testing.T, path string) []h52ObserverLine {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []h52ObserverLine
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec h52ObserverLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("observer artifact line is not valid JSON: %v (%s)", err, line)
		}
		out = append(out, rec)
	}
	return out
}

func h52ReadAudit(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit line is not valid JSON: %v (%s)", err, line)
		}
		out = append(out, ev)
	}
	return out
}

func h52ObserverFor(res h52HarnessResult, callID string) *h52ObserverLine {
	for i := range res.observer {
		if strings.Trim(string(res.observer[i].Transaction), `"`) == callID {
			return &res.observer[i]
		}
	}
	return nil
}

func h52AuditEvent(res h52HarnessResult, eventType string) map[string]any {
	for _, ev := range res.audit {
		if got, _ := ev["event_type"].(string); got == eventType {
			return ev
		}
	}
	return nil
}

// h52RequireForwarded asserts the call reached the backend and that the durable
// allow record was written before the backend observed it.
func h52RequireForwarded(t *testing.T, res h52HarnessResult, callID string) {
	t.Helper()
	if res.exited {
		t.Fatalf("%s: visor exited (code %d) instead of serving; stderr: %s", res.name, res.exitCode, res.stderr)
	}
	if !strings.Contains(res.response, "observed") {
		t.Fatalf("%s: expected the call to reach the backend, response was %q", res.name, res.response)
	}
	rec := h52ObserverFor(res, callID)
	if rec == nil {
		t.Fatalf("%s: the independent observer did not record %s; artifact said %v", res.name, callID, res.observer)
	}
	if rec.Method != "tools/call" || rec.Tool != "write_file" {
		t.Fatalf("%s: observer recorded method=%q tool=%q", res.name, rec.Method, rec.Tool)
	}
	if _, err := os.Stat(res.observerArtifact); err != nil {
		t.Fatalf("%s: observer artifact must exist and be non-empty: %v", res.name, err)
	}
	allow := h52AuditEvent(res, "tool_call_allowed")
	if allow == nil {
		t.Fatalf("%s: no durable allow event in the audit ledger; events=%v", res.name, res.audit)
	}
	allowTS, err := time.Parse(time.RFC3339Nano, fmt.Sprint(allow["timestamp"]))
	if err != nil {
		t.Fatalf("%s: unparsable audit timestamp %v: %v", res.name, allow["timestamp"], err)
	}
	recvTS, err := time.Parse(time.RFC3339Nano, rec.ReceivedAt)
	if err != nil {
		t.Fatalf("%s: unparsable observer timestamp %v: %v", res.name, rec.ReceivedAt, err)
	}
	if recvTS.Before(allowTS) {
		t.Fatalf("%s: backend received the call at %s, before the durable allow at %s", res.name, rec.ReceivedAt, allow["timestamp"])
	}
}

// h52RequireDenied asserts the backend never received the call and that the
// denial names the identity reason, so an unrelated failure cannot pass for the gate.
func h52RequireDenied(t *testing.T, res h52HarnessResult, callID, reasonContains string) {
	t.Helper()
	if res.exited {
		t.Fatalf("%s: visor exited (code %d) instead of denying the call; stderr: %s", res.name, res.exitCode, res.stderr)
	}
	if !strings.Contains(res.response, reasonContains) {
		t.Fatalf("%s: expected denial containing %q, response was %q", res.name, reasonContains, res.response)
	}
	if rec := h52ObserverFor(res, callID); rec != nil {
		t.Fatalf("%s: the backend received a call the gate denied: %+v", res.name, rec)
	}
}

// h52RequireStartupRefusal asserts the proxy refused to serve at all, which is the
// fail-closed outcome for a malformed or absent process-start context.
func h52RequireStartupRefusal(t *testing.T, res h52HarnessResult, stderrContains string) {
	t.Helper()
	if !res.exited {
		t.Fatalf("%s: expected visor to refuse to start", res.name)
	}
	if res.exitCode == 0 {
		t.Fatalf("%s: expected non-zero exit, got 0", res.name)
	}
	if !strings.Contains(res.stderr, stderrContains) {
		t.Fatalf("%s: expected stderr containing %q, got %q", res.name, stderrContains, res.stderr)
	}
	if len(res.observer) != 0 {
		t.Fatalf("%s: observer recorded %v although no call could be served", res.name, res.observer)
	}
}

// TestVerifiedActorBackendObserver is the H52 entry point. harness/identity-aware.sh
// runs exactly this test.
func TestVerifiedActorBackendObserver(t *testing.T) {
	visor := buildVisor(t)
	backend := buildH52Observer(t)

	t.Run("positive_verified_actor", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "positive", policy: h52PolicyIdentityRequired,
			actor:     h52Actor(t, nil),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireForwarded(t, res, "txn-positive")
	})

	t.Run("discriminating_control_without_identity_requirement", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "control", policy: h52PolicyNoIdentity,
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireForwarded(t, res, "txn-control")
	})

	t.Run("missing_context", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "missing-context", policy: h52PolicyIdentityRequired,
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireStartupRefusal(t, res, "require_verified_actor")
	})

	t.Run("expired_context", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "expired", policy: h52PolicyIdentityRequired,
			actor:     h52Actor(t, func(c *actorcontext.Context) { c.ExpiresAt = time.Now().UTC().Add(-time.Minute) }),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireDenied(t, res, "txn-expired", "expired")
	})

	t.Run("unsupported_verification_method", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "bad-method", policy: h52PolicyIdentityRequired,
			actor:     h52UnsealedActor(t, func(c *actorcontext.Context) { c.VerificationMethod = "mtls" }),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireStartupRefusal(t, res, "unsupported verification_method")
	})

	t.Run("required_scope_missing", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "scope-missing", policy: h52PolicyIdentityRequired,
			actor:     h52Actor(t, func(c *actorcontext.Context) { c.Scopes = []string{"read"} }),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireDenied(t, res, "txn-scope-missing", "verified actor scope missing")
	})

	t.Run("fake_identity_metadata_in_arguments", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "fake-identity", policy: h52PolicyScopeGateOnly,
			arguments: map[string]any{
				"path":            "/tmp/out.txt",
				"_verified_actor": map[string]any{"principal_id": "attacker", "scopes": []string{"read", "write"}},
				"verified_actor":  "attacker",
			},
		})
		h52RequireDenied(t, res, "txn-fake-identity", "verified actor context required")
	})

	t.Run("caller_supplied_identity_is_stripped_before_relay", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "strip-identity", policy: h52PolicyIdentityRequired,
			actor: h52Actor(t, nil),
			arguments: map[string]any{
				"path":            "/tmp/out.txt",
				"_verified_actor": map[string]any{"principal_id": "attacker"},
			},
		})
		h52RequireForwarded(t, res, "txn-strip-identity")
		rec := h52ObserverFor(res, "txn-strip-identity")
		stripped, err := json.Marshal(map[string]any{"path": "/tmp/out.txt"})
		if err != nil {
			t.Fatal(err)
		}
		want := h52SHA256(stripped)
		if rec.ArgsSHA256 != want {
			t.Fatalf("backend received arguments that still carry caller-supplied identity: got %s, want the hash of %s", rec.ArgsSHA256, stripped)
		}
	})

	t.Run("caller_override_of_principal", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "override-principal", policy: h52PolicyScopeGateOnly,
			arguments: map[string]any{
				"path":         "/tmp/out.txt",
				"principal_id": "attacker",
				"acting_agent": "attacker",
			},
		})
		h52RequireDenied(t, res, "txn-override-principal", "verified actor context required")
	})

	t.Run("truncated_actor_payload", func(t *testing.T) {
		full := h52Actor(t, nil)
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "truncated", policy: h52PolicyIdentityRequired,
			actor:     full[:len(full)/2],
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireStartupRefusal(t, res, "verified actor context")
	})

	t.Run("trailing_json_actor_payload", func(t *testing.T) {
		full := h52Actor(t, nil)
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "trailing", policy: h52PolicyIdentityRequired,
			actor:     append(append([]byte{}, full...), []byte("\n{}")...),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireStartupRefusal(t, res, "trailing data")
	})

	t.Run("actor_expires_while_approval_pending", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "approval-expiry", policy: h52PolicyApprovalRequired,
			actor:         h52Actor(t, func(c *actorcontext.Context) { c.ExpiresAt = time.Now().UTC().Add(3 * time.Second) }),
			arguments:     map[string]any{"path": "/tmp/out.txt"},
			approvalDelay: 5 * time.Second,
		})
		h52RequireDenied(t, res, "txn-approval-expiry", "expired")
	})

	// H52 gap probe, not an acceptance case: the decision path does not check the
	// context audience, so a wrong audience is measured as forwarded rather than
	// denied. This records the measurement; closing it requires an enforcement
	// change, which is a separate security-classified card.
	t.Run("gap_probe_wrong_audience_is_not_enforced", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "audience-gap", policy: h52PolicyIdentityRequired,
			actor:     h52Actor(t, func(c *actorcontext.Context) { c.Audience = "https://attacker.example.test" }),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		if h52ObserverFor(res, "txn-audience-gap") == nil {
			t.Logf("H52 GAP CLOSED: a wrong audience is now denied; update harness/invariants.md H52 and delete the gap note")
			return
		}
		t.Logf("H52 GAP: audience is not enforced in the decision path; a context with audience %q was forwarded to the backend. Enforcement is a separate security-classified change.", "https://attacker.example.test")
	})
}
