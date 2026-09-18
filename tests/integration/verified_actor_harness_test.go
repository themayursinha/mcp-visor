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
//
// Three assertion rules keep the deny leg non-vacuous:
//
//   - the recorded argument hash covers the raw argument bytes as received, with
//     no decode/re-marshal round trip;
//   - the denial reason is read from the JSON-RPC `error.message` only, never from
//     the whole response, whose echoed request id contains the reason words;
//   - a deny scenario is judged only against an authenticated complete observer
//     session, so an unreadable, empty or incomplete artifact fails as UNKNOWN
//     instead of passing by omission.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/actorcontext"
)

// h52SessionSeq makes observer artifact and FIFO paths unique across -count=N
// runs inside one process, including when H52_ARTIFACT_DIR is shared.
var h52SessionSeq atomic.Uint64

// h52ObserverSource is the independent backend observer. Standard library only:
// its single input is the bytes it receives on stdin.
const h52ObserverSource = `package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

type startRec struct {
	Event    string ` + "`json:\"event\"`" + `
	Scenario string ` + "`json:\"scenario\"`" + `
	PID      int    ` + "`json:\"pid\"`" + `
	Time     string ` + "`json:\"time\"`" + `
}

type callRec struct {
	Record      string          ` + "`json:\"record\"`" + `
	ReceivedAt  string          ` + "`json:\"received_at\"`" + `
	Transaction json.RawMessage ` + "`json:\"transaction\"`" + `
	Method      string          ` + "`json:\"method\"`" + `
	Tool        string          ` + "`json:\"tool\"`" + `
	ArgsSHA256  string          ` + "`json:\"args_sha256\"`" + `
}

type endRec struct {
	Event        string   ` + "`json:\"event\"`" + `
	Scenario     string   ` + "`json:\"scenario\"`" + `
	Calls        int      ` + "`json:\"calls\"`" + `
	Bytes        int      ` + "`json:\"bytes\"`" + `
	SHA256       string   ` + "`json:\"sha256\"`" + `
	Transactions []string ` + "`json:\"transactions\"`" + `
}

type errorRec struct {
	Event  string ` + "`json:\"event\"`" + `
	Detail string ` + "`json:\"detail\"`" + `
	Calls  int    ` + "`json:\"calls\"`" + `
}

func main() {
	signal.Ignore(syscall.SIGPIPE)

	scenario := os.Getenv("H52_SCENARIO")
	var f *os.File
	calls := 0
	var txns []string
	prefix := sha256.New()
	prefixN := 0

	fail := func(detail string) {
		rec, _ := json.Marshal(errorRec{Event: "observer_error", Detail: detail, Calls: calls})
		if f != nil {
			_ = writeRec(f, rec)
		}
		writeFIFO(rec)
		os.Exit(2)
	}

	var err error
	f, err = os.OpenFile(os.Getenv("OBSERVER_LOG"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		fail("open artifact: " + err.Error())
	}
	defer f.Close()

	start, err := json.Marshal(startRec{
		Event:    "start",
		Scenario: scenario,
		PID:      os.Getpid(),
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		fail("marshal start: " + err.Error())
	}
	if err := writePrefix(f, prefix, &prefixN, start); err != nil {
		fail("write start: " + err.Error())
	}

	in := bufio.NewReader(os.Stdin)
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(line) > 0 {
					fail("non-empty leftover bytes at EOF")
				}
				ids := make([]string, len(txns))
				copy(ids, txns)
				sort.Strings(ids)
				end, mErr := json.Marshal(endRec{
					Event:        "end",
					Scenario:     scenario,
					Calls:        calls,
					Bytes:        prefixN,
					SHA256:       hex.EncodeToString(prefix.Sum(nil)),
					Transactions: ids,
				})
				if mErr != nil {
					fail("marshal end: " + mErr.Error())
				}
				if wErr := writeRec(f, end); wErr != nil {
					fail("write end: " + wErr.Error())
				}
				writeFIFO(end)
				return
			}
			fail("stdin: " + err.Error())
		}
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}

		var req struct {
			ID     json.RawMessage
			Method string
			Params json.RawMessage
		}
		if err := json.Unmarshal(line, &req); err != nil || req.Method == "" {
			fail("stdin line is not a JSON object with a string method")
		}

		var params struct {
			Name      string
			Arguments json.RawMessage
		}
		_ = json.Unmarshal(req.Params, &params)

		switch req.Method {
		case "initialize":
			_, _ = fmt.Fprintf(os.Stdout, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"observer-backend\",\"version\":\"1\"}}}\n", rawID(req.ID))
		case "tools/call":
			sum := sha256.Sum256(params.Arguments)
			rec, mErr := json.Marshal(callRec{
				Record:      "call",
				ReceivedAt:  time.Now().UTC().Format(time.RFC3339Nano),
				Transaction: req.ID,
				Method:      req.Method,
				Tool:        params.Name,
				ArgsSHA256:  hex.EncodeToString(sum[:]),
			})
			if mErr != nil {
				fail("marshal call: " + mErr.Error())
			}
			if wErr := writePrefix(f, prefix, &prefixN, rec); wErr != nil {
				fail("write call: " + wErr.Error())
			}
			calls++
			txns = append(txns, txnID(req.ID))
			_, _ = fmt.Fprintf(os.Stdout, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"observed\"}]}}\n", rawID(req.ID))
		default:
			if !nullID(req.ID) {
				_, _ = fmt.Fprintf(os.Stdout, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n", rawID(req.ID))
			}
		}
	}
}

func writePrefix(f *os.File, prefix hash.Hash, prefixN *int, rec []byte) error {
	line := make([]byte, len(rec)+1)
	copy(line, rec)
	line[len(rec)] = '\n'
	n, err := f.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return fmt.Errorf("short write: %d != %d", n, len(line))
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if _, err := prefix.Write(line); err != nil {
		return err
	}
	*prefixN += len(line)
	return nil
}

func writeRec(f *os.File, rec []byte) error {
	line := make([]byte, len(rec)+1)
	copy(line, rec)
	line[len(rec)] = '\n'
	n, err := f.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return fmt.Errorf("short write: %d != %d", n, len(line))
	}
	return f.Sync()
}

func writeFIFO(rec []byte) {
	path := os.Getenv("H52_COMPLETION_FIFO")
	if path == "" {
		return
	}
	out, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	line := make([]byte, len(rec)+1)
	copy(line, rec)
	line[len(rec)] = '\n'
	_, _ = out.Write(line)
	_ = out.Close()
}

func rawID(v json.RawMessage) string {
	if len(v) == 0 {
		return "null"
	}
	return string(v)
}

func nullID(v json.RawMessage) bool {
	return len(v) == 0 || string(v) == "null"
}

func txnID(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
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
  approval_timeout_seconds: 45
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

type h52TerminalRecord struct {
	Event        string   `json:"event"`
	Scenario     string   `json:"scenario"`
	Calls        int      `json:"calls"`
	Bytes        int      `json:"bytes"`
	SHA256       string   `json:"sha256"`
	Transactions []string `json:"transactions"`
	Detail       string   `json:"detail"`
}

type h52HarnessResult struct {
	name             string
	response         string
	stderr           string
	exited           bool
	exitCode         int
	observerArtifact string
	audit            []map[string]any
	callSent         bool
	completionLine   string
	clientByID       map[string][]string
	sentCallIDs      []string
	callID           string
	barrierID        string
	expiresAt        time.Time
	callSentAt       time.Time
	requestFileAt    time.Time
	grantAt          time.Time
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

// h52MultiAudienceActor returns a structurally plausible process-start payload
// whose audience is an array. VerifiedActorContext v1 carries exactly one audience
// string, so a client offering several audiences is refused at process start rather
// than denied at the call gate: the acceptance row "multiple audiences where exactly
// one is required" is proven here as a startup refusal, not as a runtime deny.
func h52MultiAudienceActor(t *testing.T) []byte {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(h52Actor(t, nil), &payload); err != nil {
		t.Fatalf("decode actor payload: %v", err)
	}
	payload["audience"] = []string{"https://visor-gateway.example.test", "https://second.example.test"}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal multi-audience payload: %v", err)
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
	name             string
	policy           string
	actor            []byte
	arguments        map[string]any
	expiresAt        time.Time
	grantAfterExpiry bool
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
	fifoPath, fifo := h52CreateArmedFIFO(t)
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
	if opts.grantAfterExpiry {
		approvalDir = filepath.Join(dir, "approvals")
		if err := os.MkdirAll(approvalDir, 0o700); err != nil {
			t.Fatalf("create approval dir: %v", err)
		}
		args = append(args, "-approval-dir", approvalDir)
	}

	cmd := exec.Command(visor, args...)
	cmd.Env = append(os.Environ(),
		"OBSERVER_LOG="+observerLog,
		"H52_SCENARIO="+opts.name,
		"H52_COMPLETION_FIFO="+fifoPath,
	)
	cmd.ExtraFiles = extraFiles
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("client stdout pipe: %v", err)
	}
	cmd.Stdout = pw
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		t.Fatalf("start visor: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close client stdout write end: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = pr.Close()
	})

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(pr)
	clientByID := map[string][]string{}
	res.clientByID = clientByID
	res.expiresAt = opts.expiresAt

	loadArtifacts := func() {
		res.stderr = stderrBuf.String()
		res.audit = h52ReadAudit(t, auditLog)
		res.clientByID = clientByID
	}

	callID := "txn-" + opts.name
	const barrierID = "h52-barrier"
	res.callID = callID
	res.barrierID = barrierID

	initMsg := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "h52-harness", "version": "1.0.0"}},
	}
	if err := h52Send(w, initMsg); err != nil {
		t.Fatalf("send initialize: %v", err)
	}

	initCh := make(chan h52LineRead, 1)
	go func() {
		line, err := r.ReadString('\n')
		initCh <- h52LineRead{line: strings.TrimSpace(line), err: err}
	}()

	select {
	case waitErr := <-waitCh:
		res.exited = true
		res.exitCode = h52ExitCode(waitErr)
		h52CollectPendingLine(initCh, clientByID)
		loadArtifacts()
		return res
	case got := <-initCh:
		if got.err != nil || got.line == "" {
			select {
			case waitErr := <-waitCh:
				res.exited = true
				res.exitCode = h52ExitCode(waitErr)
				loadArtifacts()
				return res
			case <-time.After(20 * time.Second):
				t.Fatalf("H52 UNKNOWN: timed out waiting for client response id 1")
			}
		}
		id := h52JSONRPCID(got.line)
		clientByID[id] = append(clientByID[id], got.line)
		if id != "1" {
			res.response = h52AwaitClient(t, r, clientByID, "1", 20*time.Second)
		} else {
			res.response = got.line
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("H52 UNKNOWN: timed out waiting for client response id 1")
	}

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
	res.callSentAt = callAt
	res.sentCallIDs = []string{callID}

	if opts.grantAfterExpiry {
		id, requestAt, early, _ := h52WaitApprovalRequest(t, approvalDir, pr, r, clientByID, callID, 15*time.Second)
		res.requestFileAt = requestAt
		grantAt := opts.expiresAt.Add(time.Second)
		if now := time.Now(); now.After(grantAt) {
			grantAt = now
		}
		res.grantAt = grantAt
		if early != "" {
			t.Fatalf("%s: client decision for %s arrived before the approval request file; expiresAt=%s callSentAt=%s requestFileAt=%s grantAt=%s",
				opts.name, callID,
				opts.expiresAt.UTC().Format(time.RFC3339Nano),
				callAt.UTC().Format(time.RFC3339Nano),
				requestAt.UTC().Format(time.RFC3339Nano),
				grantAt.UTC().Format(time.RFC3339Nano))
		}
		if err := pr.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear client stream deadline: %v", err)
		}
		if wait := time.Until(grantAt); wait > 0 {
			timer := time.NewTimer(wait)
			<-timer.C
		}
		res.grantAt = time.Now()
		// A discarded grant error turns a slow or unwritable runner into an
		// opaque approval timeout; fail the scenario instead.
		if err := os.WriteFile(filepath.Join(approvalDir, "req-"+id+".ok"), []byte{}, 0o600); err != nil {
			t.Fatalf("%s: grant approval for %s: %v", opts.name, id, err)
		}
	}

	res.response = h52AwaitClient(t, r, clientByID, callID, 30*time.Second)

	if err := h52Send(w, map[string]any{
		"jsonrpc": "2.0", "id": barrierID, "method": "tools/list",
		"params": map[string]any{},
	}); err != nil {
		t.Fatalf("send tools/list barrier: %v", err)
	}
	_ = h52AwaitClient(t, r, clientByID, barrierID, 30*time.Second)

	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	<-waitCh
	h52DrainClient(r, clientByID)
	res.completionLine = h52ReadCompletion(t, fifo, 10*time.Second)
	loadArtifacts()
	return res
}

// h52ObserverPath returns where the independent observer records this scenario.
// A verification command must not change the repository snapshot digest, so the
// artifact goes to a temp directory unless the harness entry point sets
// H52_ARTIFACT_DIR, which points at the digest-excluded evidence/harness tree.
// The file name includes pid and a process-local sequence so -count=N in one
// process cannot collide under O_EXCL when H52_ARTIFACT_DIR is shared.
func h52ObserverPath(t *testing.T, scenario string) string {
	t.Helper()
	n := h52SessionSeq.Add(1)
	name := fmt.Sprintf("%s-%d-%d.jsonl", scenario, os.Getpid(), n)
	if dir := strings.TrimSpace(os.Getenv("H52_ARTIFACT_DIR")); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create H52_ARTIFACT_DIR: %v", err)
		}
		return filepath.Join(dir, name)
	}
	return filepath.Join(t.TempDir(), name)
}

func h52CreateArmedFIFO(t *testing.T) (string, *os.File) {
	t.Helper()
	n := h52SessionSeq.Add(1)
	path := filepath.Join(t.TempDir(), fmt.Sprintf("h52-%d-%d.fifo", os.Getpid(), n))
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create completion fifo: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("arm completion fifo: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return path, f
}

func h52JSONRPCID(line string) string {
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return ""
	}
	if len(msg.ID) == 0 || string(msg.ID) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(msg.ID, &s) == nil {
		return s
	}
	return string(msg.ID)
}

func h52AwaitClient(t *testing.T, r *bufio.Reader, byID map[string][]string, wantID string, timeout time.Duration) string {
	t.Helper()
	if lines := byID[wantID]; len(lines) > 0 {
		return lines[0]
	}
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			t.Fatalf("H52 UNKNOWN: timed out waiting for client response id %s", wantID)
		}
		line, ok := h52ReadLine(t, r, remain)
		if !ok {
			t.Fatalf("H52 UNKNOWN: timed out waiting for client response id %s", wantID)
		}
		if line == "" {
			continue
		}
		id := h52JSONRPCID(line)
		byID[id] = append(byID[id], line)
		if id == wantID {
			return line
		}
	}
}

func h52DrainClient(r *bufio.Reader, byID map[string][]string) {
	for {
		line, err := r.ReadString('\n')
		if s := strings.TrimSpace(line); s != "" {
			id := h52JSONRPCID(s)
			byID[id] = append(byID[id], s)
		}
		if err != nil {
			return
		}
	}
}

func h52ReadCompletion(t *testing.T, fifo *os.File, timeout time.Duration) string {
	t.Helper()
	if err := fifo.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("H52 UNKNOWN: set completion fifo deadline: %v", err)
	}
	line, err := bufio.NewReader(fifo).ReadString('\n')
	if err != nil {
		t.Fatalf("H52 UNKNOWN: the observer session did not complete (%v)", err)
	}
	return strings.TrimSpace(line)
}

func h52TryReadCompletion(fifo *os.File, timeout time.Duration) (string, error) {
	if err := fifo.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(fifo).ReadString('\n')
	return strings.TrimSpace(line), err
}

func h52ArtifactPrefix(raw []byte) (prefix, terminal []byte) {
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	idx := bytes.LastIndexByte(trimmed, '\n')
	if idx < 0 {
		return nil, trimmed
	}
	return trimmed[:idx+1], trimmed[idx+1:]
}

func h52StartObserverProcess(t *testing.T, backend, scenario string) (stdin io.WriteCloser, fifo *os.File, artifact string, cmd *exec.Cmd) {
	t.Helper()
	artifact = h52ObserverPath(t, scenario)
	fifoPath, fifo := h52CreateArmedFIFO(t)
	cmd = exec.Command(backend)
	cmd.Env = append(os.Environ(),
		"OBSERVER_LOG="+artifact,
		"H52_SCENARIO="+scenario,
		"H52_COMPLETION_FIFO="+fifoPath,
	)
	var err error
	stdin, err = cmd.StdinPipe()
	if err != nil {
		t.Fatalf("observer stdin: %v", err)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start observer: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState != nil {
			return
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	return stdin, fifo, artifact, cmd
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

type h52LineRead struct {
	line string
	err  error
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

func h52CollectPendingLine(ch <-chan h52LineRead, clientByID map[string][]string) {
	select {
	case got := <-ch:
		if got.line == "" {
			return
		}
		id := h52JSONRPCID(got.line)
		clientByID[id] = append(clientByID[id], got.line)
	default:
	}
}

func h52WaitApprovalRequest(t *testing.T, dir string, pr *os.File, r *bufio.Reader, clientByID map[string][]string, callID string, timeout time.Duration) (id string, requestAt time.Time, earlyDecision string, decisionAt time.Time) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		now := time.Now()
		if !now.Before(deadline) {
			t.Fatalf("no approval request appeared in %s within %s", dir, timeout)
		}
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, "req-") && strings.HasSuffix(name, ".json") {
					return strings.TrimSuffix(strings.TrimPrefix(name, "req-"), ".json"), time.Now(), "", time.Time{}
				}
			}
		}
		remain := time.Until(deadline)
		slice := 25 * time.Millisecond
		if remain < slice {
			slice = remain
		}
		if slice <= 0 {
			continue
		}
		if err := pr.SetReadDeadline(time.Now().Add(slice)); err != nil {
			t.Fatalf("set client stream deadline: %v", err)
		}
		line, err := r.ReadString('\n')
		if err == nil {
			s := strings.TrimSpace(line)
			if s == "" {
				continue
			}
			lineID := h52JSONRPCID(s)
			clientByID[lineID] = append(clientByID[lineID], s)
			if lineID == callID {
				return "", time.Time{}, s, time.Now()
			}
			continue
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
	}
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

func h52AuditEvent(res h52HarnessResult, eventType string) map[string]any {
	for _, ev := range res.audit {
		if got, _ := ev["event_type"].(string); got == eventType {
			return ev
		}
	}
	return nil
}

func h52TxnString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func h52SentCall(ids []string, id string) bool {
	for _, got := range ids {
		if got == id {
			return true
		}
	}
	return false
}

func h52SameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func h52JSONRPCOutcome(line string) (hasResult, hasError bool, errMsg string) {
	var msg struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return false, false, ""
	}
	hasResult = len(msg.Result) > 0 && string(msg.Result) != "null"
	if msg.Error != nil {
		return hasResult, true, msg.Error.Message
	}
	return hasResult, false, ""
}

func h52ResultTextObserved(line string) bool {
	var msg struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return false
	}
	for _, c := range msg.Result.Content {
		if c.Text == "observed" {
			return true
		}
	}
	return false
}

func h52ClientLine(res h52HarnessResult, id string) string {
	if lines := res.clientByID[id]; len(lines) > 0 {
		return lines[0]
	}
	if id == res.callID {
		return res.response
	}
	return ""
}

func h52RequireClientCardinality(t *testing.T, res h52HarnessResult, callID string, callMustBeResult bool) {
	t.Helper()
	barrierID := res.barrierID
	if barrierID == "" {
		barrierID = "h52-barrier"
	}
	want := []string{"1", callID, barrierID}
	for _, id := range want {
		lines := res.clientByID[id]
		if len(lines) == 0 {
			t.Fatalf("H52 UNKNOWN: timed out waiting for client response id %s", id)
		}
		if len(lines) > 1 {
			t.Fatalf("%s: extra client response for id %s: %q", res.name, id, lines)
		}
		hasResult, hasError, _ := h52JSONRPCOutcome(lines[0])
		if hasResult && hasError {
			t.Fatalf("%s: client id %s carried both an error and a result: %q", res.name, id, lines[0])
		}
		switch id {
		case "1", barrierID:
			if !hasResult || hasError {
				t.Fatalf("%s: extra client response for id %s: %q", res.name, id, lines[0])
			}
		default:
			if callMustBeResult {
				if !hasResult || hasError || !h52ResultTextObserved(lines[0]) {
					t.Fatalf("%s: expected the call to reach the backend, response was %q", res.name, lines[0])
				}
			} else if !hasError || hasResult {
				t.Fatalf("%s: expected a JSON-RPC error response, got %q", res.name, lines[0])
			}
		}
	}
	for id, lines := range res.clientByID {
		if id == "1" || id == callID || id == barrierID {
			continue
		}
		t.Fatalf("%s: extra client response for id %s: %q", res.name, id, lines)
	}
}

// h52DecideBackendReceipt authenticates the observer session and returns the
// record for callID (nil if the authenticated session has none). Every error
// already carries its final text: UNKNOWN reasons, the named leak, or the
// named missing-receive failure. Scenarios must not call this; they go through
// h52BackendReceipt, which fatals on any error.
func h52DecideBackendReceipt(res h52HarnessResult, callID string, wantReceived *bool) (*h52ObserverLine, error) {
	if res.completionLine == "" {
		return nil, fmt.Errorf("H52 UNKNOWN: the observer session did not complete (no terminal record)")
	}
	var term h52TerminalRecord
	if err := json.Unmarshal([]byte(res.completionLine), &term); err != nil {
		return nil, fmt.Errorf("H52 UNKNOWN: completion record is not JSON: %v", err)
	}
	if term.Event == "observer_error" {
		return nil, fmt.Errorf("H52 UNKNOWN: observer error: %s", term.Detail)
	}
	if term.Event != "end" {
		return nil, fmt.Errorf("H52 UNKNOWN: the observer session did not complete (terminal event=%s)", term.Event)
	}
	if term.Scenario != res.name {
		return nil, fmt.Errorf("H52 UNKNOWN: completion end scenario=%q, want %q", term.Scenario, res.name)
	}

	raw, err := os.ReadFile(res.observerArtifact)
	if err != nil {
		return nil, fmt.Errorf("H52 UNKNOWN: observer artifact is unreadable: %v", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("H52 UNKNOWN: observer artifact is empty")
	}
	prefix, endLine := h52ArtifactPrefix(raw)
	if string(endLine) != res.completionLine {
		return nil, fmt.Errorf("H52 UNKNOWN: artifact end line is not byte-identical to the completion record")
	}

	var lines [][]byte
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("H52 UNKNOWN: observer artifact is empty")
	}
	lines = bytes.Split(trimmed, []byte("\n"))
	if len(lines) < 2 {
		return nil, fmt.Errorf("H52 UNKNOWN: start record missing or not first")
	}

	var start struct {
		Event    string `json:"event"`
		Scenario string `json:"scenario"`
	}
	if err := json.Unmarshal(lines[0], &start); err != nil || start.Event != "start" {
		return nil, fmt.Errorf("H52 UNKNOWN: start record missing or not first")
	}
	if start.Scenario != res.name {
		return nil, fmt.Errorf("H52 UNKNOWN: start scenario=%q, want %q", start.Scenario, res.name)
	}

	var last struct {
		Event  string `json:"event"`
		Record string `json:"record"`
	}
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil || last.Event != "end" {
		return nil, fmt.Errorf("H52 UNKNOWN: end record is not last")
	}

	var calls []h52ObserverLine
	for _, line := range lines {
		var probe struct {
			Event  string `json:"event"`
			Record string `json:"record"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("H52 UNKNOWN: observer artifact line is not JSON: %v", err)
		}
		if probe.Event == "observer_error" {
			return nil, fmt.Errorf("H52 UNKNOWN: observer error: %s", probe.Detail)
		}
		if probe.Record == "call" {
			var rec h52ObserverLine
			if err := json.Unmarshal(line, &rec); err != nil {
				return nil, fmt.Errorf("H52 UNKNOWN: call record is not JSON: %v", err)
			}
			calls = append(calls, rec)
		}
	}

	if term.Bytes != len(prefix) {
		return nil, fmt.Errorf("H52 UNKNOWN: end.bytes=%d does not match artifact prefix length %d", term.Bytes, len(prefix))
	}
	if term.SHA256 != h52SHA256(prefix) {
		return nil, fmt.Errorf("H52 UNKNOWN: end.sha256 does not match artifact prefix digest")
	}
	if term.Calls != len(calls) {
		return nil, fmt.Errorf("H52 UNKNOWN: end.calls=%d does not match recorded call count %d", term.Calls, len(calls))
	}
	recorded := make([]string, len(calls))
	for i := range calls {
		recorded[i] = h52TxnString(calls[i].Transaction)
	}
	sorted := append([]string(nil), recorded...)
	sort.Strings(sorted)
	if !h52SameStrings(term.Transactions, sorted) {
		return nil, fmt.Errorf("H52 UNKNOWN: end.transactions does not match recorded ids")
	}

	nMatch := 0
	var found *h52ObserverLine
	for i := range calls {
		id := recorded[i]
		if id == callID {
			nMatch++
			rec := calls[i]
			found = &rec
			continue
		}
		if !h52SentCall(res.sentCallIDs, id) {
			return nil, fmt.Errorf("H52 UNKNOWN: observer recorded a transaction the scenario never sent: %s", id)
		}
	}
	if nMatch > 1 {
		return nil, fmt.Errorf("H52 UNKNOWN: duplicate call record for %s", callID)
	}

	if wantReceived != nil {
		if *wantReceived {
			if found == nil {
				return nil, fmt.Errorf("the expected call never reached the backend (session calls=%d)", term.Calls)
			}
			return found, nil
		}
		if found != nil {
			return found, fmt.Errorf("the backend received a call the gate denied: %s", h52TxnString(found.Transaction))
		}
		return nil, nil
	}
	return found, nil
}

// h52BackendReceipt is the only way a scenario reaches the session validator.
// It fatals on any error, so UNKNOWN cannot be ignored.
func h52BackendReceipt(t *testing.T, res h52HarnessResult, callID string) *h52ObserverLine {
	t.Helper()
	rec, err := h52DecideBackendReceipt(res, callID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func h52GapReceipt(t *testing.T, res h52HarnessResult, callID string) *h52ObserverLine {
	t.Helper()
	rec, err := h52DecideBackendReceipt(res, callID, nil)
	if err != nil {
		t.Fatalf("the audience gap is unmeasured: %s", err)
	}
	return rec
}

func h52ObserverSession(t *testing.T, backend, scenario string, stdinLines []string) h52HarnessResult {
	t.Helper()
	stdin, fifo, artifact, cmd := h52StartObserverProcess(t, backend, scenario)
	var sent []string
	for _, line := range stdinLines {
		if _, err := io.WriteString(stdin, line+"\n"); err != nil {
			t.Fatalf("write observer stdin: %v", err)
		}
		if id := h52JSONRPCID(line); id != "" && strings.Contains(line, `"method":"tools/call"`) {
			sent = append(sent, id)
		}
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close observer stdin: %v", err)
	}
	completion := h52ReadCompletion(t, fifo, 10*time.Second)
	_ = cmd.Wait()
	return h52HarnessResult{
		name:             scenario,
		observerArtifact: artifact,
		completionLine:   completion,
		sentCallIDs:      sent,
	}
}

func h52StdoutPipeParentUnknown(t *testing.T, visor, backend string) error {
	t.Helper()
	dir := t.TempDir()
	observerLog := h52ObserverPath(t, "stdout-pipe")
	fifoPath, fifo := h52CreateArmedFIFO(t)
	t.Cleanup(func() { _ = fifo.Close() })
	auditLog := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(fmt.Sprintf(h52PolicyIdentityRequired, backend)), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	actorPath := filepath.Join(dir, "actor.json")
	if err := os.WriteFile(actorPath, h52Actor(t, func(c *actorcontext.Context) {
		c.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	}), 0o600); err != nil {
		t.Fatalf("write actor: %v", err)
	}
	f, err := os.Open(actorPath)
	if err != nil {
		t.Fatalf("open actor: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	cmd := exec.Command(visor, "serve", "-server", backend, "-policy", policyPath, "-audit-log", auditLog,
		"-session-id", "sess-h52-stdout-pipe", "-client-id", "h52-client", "-verified-actor-fd", "3")
	cmd.Env = append(os.Environ(),
		"OBSERVER_LOG="+observerLog,
		"H52_SCENARIO=stdout-pipe",
		"H52_COMPLETION_FIFO="+fifoPath,
	)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)
	if err := h52Send(w, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "h52-harness", "version": "1.0.0"}},
	}); err != nil {
		t.Fatalf("send initialize: %v", err)
	}
	initLine, ok := h52ReadLine(t, r, 20*time.Second)
	if !ok || h52JSONRPCID(initLine) != "1" {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return fmt.Errorf("H52 UNKNOWN: timed out waiting for client response id 1")
	}
	if err := h52Send(w, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatalf("send initialized: %v", err)
	}
	if err := h52Send(w, map[string]any{
		"jsonrpc": "2.0", "id": "txn-stdout-pipe", "method": "tools/call",
		"params": map[string]any{"name": "write_file", "arguments": map[string]any{"path": "/tmp/out.txt"}},
	}); err != nil {
		t.Fatalf("send tools/call: %v", err)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	data, readErr := io.ReadAll(stdout)
	_ = waitErr
	for _, line := range strings.Split(string(bytes.TrimSpace(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hasResult, hasError, _ := h52JSONRPCOutcome(line)
		id := h52JSONRPCID(line)
		if hasError && !hasResult && id == "txn-stdout-pipe" {
			return nil
		}
	}
	if readErr != nil {
		return fmt.Errorf("H52 UNKNOWN: timed out waiting for client response id txn-stdout-pipe (%v)", readErr)
	}
	return fmt.Errorf("H52 UNKNOWN: timed out waiting for client response id txn-stdout-pipe")
}

func h52CompleteArtifactCalls(path string) (calls int, complete bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return 0, false
	}
	prefix, endLine := h52ArtifactPrefix(raw)
	var term h52TerminalRecord
	if json.Unmarshal(endLine, &term) != nil || term.Event != "end" {
		return 0, false
	}
	if term.Bytes != len(prefix) || term.SHA256 != h52SHA256(prefix) {
		return 0, false
	}
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	lines := bytes.Split(trimmed, []byte("\n"))
	if len(lines) < 2 {
		return 0, false
	}
	var start struct {
		Event string `json:"event"`
	}
	if json.Unmarshal(lines[0], &start) != nil || start.Event != "start" {
		return 0, false
	}
	n := 0
	for i, line := range lines {
		var probe struct {
			Event  string `json:"event"`
			Record string `json:"record"`
		}
		if json.Unmarshal(line, &probe) != nil {
			return 0, false
		}
		if probe.Event == "observer_error" {
			return 0, false
		}
		if probe.Record == "call" {
			n++
		}
		if i == len(lines)-1 && probe.Event != "end" {
			return 0, false
		}
	}
	if term.Calls != n {
		return 0, false
	}
	return n, true
}

// h52RequireForwarded asserts the call reached the backend and that the durable
// allow record was written before the backend observed it.
func h52RequireForwarded(t *testing.T, res h52HarnessResult, callID string) *h52ObserverLine {
	t.Helper()
	if res.exited {
		t.Fatalf("%s: visor exited (code %d) instead of serving; stderr: %s", res.name, res.exitCode, res.stderr)
	}
	rec := h52BackendReceipt(t, res, callID)
	if rec == nil {
		n := 0
		var term h52TerminalRecord
		if json.Unmarshal([]byte(res.completionLine), &term) == nil {
			n = term.Calls
		}
		t.Fatalf("%s: the expected call never reached the backend (session calls=%d)", res.name, n)
	}
	h52RequireClientCardinality(t, res, callID, true)
	if rec.Method != "tools/call" || rec.Tool != "write_file" {
		t.Fatalf("%s: observer recorded method=%q tool=%q", res.name, rec.Method, rec.Tool)
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
	return rec
}

// h52DenyMessage returns the JSON-RPC `error.message` of a denial and checks that
// the response is an error correlated to callID. The reason leg must be read from
// that field and nothing else: a denial response also echoes the request id, and
// ids such as "txn-expired" already contain the reason words, so a substring match
// over the whole response would be satisfied by any denial at all.
func h52DenyMessage(t *testing.T, res h52HarnessResult, callID string) string {
	t.Helper()
	line := h52ClientLine(res, callID)
	var resp struct {
		ID    json.RawMessage
		Error *struct {
			Code    int
			Message string
		}
	}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("%s: denial response is not a JSON-RPC object: %v (%q)", res.name, err, line)
	}
	if resp.Error == nil {
		t.Fatalf("%s: expected a JSON-RPC error response, got %q", res.name, line)
	}
	if got := strings.Trim(string(resp.ID), `"`); got != callID {
		t.Fatalf("%s: denial response is not correlated to transaction %s: response id %q", res.name, callID, got)
	}
	return resp.Error.Message
}

// h52RequireDenied asserts the backend never received the call, that the observer
// session was authenticated, and that the denial names the identity reason, so an
// unrelated failure cannot pass for the gate.
func h52RequireDenied(t *testing.T, res h52HarnessResult, callID, reasonContains string) {
	t.Helper()
	if res.exited {
		t.Fatalf("%s: visor exited (code %d) instead of denying the call; stderr: %s", res.name, res.exitCode, res.stderr)
	}
	rec := h52BackendReceipt(t, res, callID)
	if rec != nil {
		t.Fatalf("%s: the backend received a call the gate denied: %s", res.name, h52TxnString(rec.Transaction))
	}
	h52RequireClientCardinality(t, res, callID, false)
	message := h52DenyMessage(t, res, callID)
	if !strings.Contains(message, reasonContains) {
		t.Fatalf("%s: expected the JSON-RPC error.message to name %q, got %q (an echoed request id must not satisfy this leg)", res.name, reasonContains, message)
	}
}

// h52RequireStartupRefusal asserts the proxy refused to serve at all, which is the
// fail-closed outcome for a malformed or absent process-start context. Evidence is
// process-level only: these scenarios are refusals, not gate denials, and they are
// never correlated by transaction id.
func h52RequireStartupRefusal(t *testing.T, res h52HarnessResult, stderrContains string) {
	t.Helper()
	if !res.exited {
		t.Fatalf("%s: expected visor to refuse to start; exit=%d stderr=%s", res.name, res.exitCode, res.stderr)
	}
	if res.exitCode == 0 {
		t.Fatalf("%s: expected visor to refuse to start; exit=0 stderr=%s", res.name, res.stderr)
	}
	if !strings.Contains(res.stderr, stderrContains) {
		t.Fatalf("%s: expected visor to refuse to start; exit=%d stderr=%s", res.name, res.exitCode, res.stderr)
	}
	if lines := res.clientByID["1"]; len(lines) > 0 {
		if hasResult, hasError, _ := h52JSONRPCOutcome(lines[0]); hasResult && !hasError {
			t.Fatalf("%s: expected visor to refuse to start; exit=%d stderr=%s", res.name, res.exitCode, res.stderr)
		}
	}
	if res.callSent {
		t.Fatalf("%s: expected visor to refuse to start; exit=%d stderr=%s", res.name, res.exitCode, res.stderr)
	}
	// Documented boundary (design contract §4.7): refusal legs exit before the proxy can spawn the observer, so an absent or incomplete session is expected.
	if n, complete := h52CompleteArtifactCalls(res.observerArtifact); complete && n != 0 {
		t.Fatalf("%s: expected visor to refuse to start; complete observer session has %d call record(s); exit=%d stderr=%s", res.name, n, res.exitCode, res.stderr)
	}
}

// TestVerifiedActorBackendObserver is the H52 entry point. harness/identity-aware.sh
// runs exactly this test.
func TestVerifiedActorBackendObserver(t *testing.T) {
	backend := buildH52Observer(t)

	t.Run("observer_tools_call_then_eof_writes_end", func(t *testing.T) {
		stdin, fifo, artifact, cmd := h52StartObserverProcess(t, backend, "observer-eof")
		call := `{"jsonrpc":"2.0","id":"txn-observer-eof","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/out.txt"}}}` + "\n"
		if _, err := io.WriteString(stdin, call); err != nil {
			t.Fatalf("write tools/call: %v", err)
		}
		if err := stdin.Close(); err != nil {
			t.Fatalf("close observer stdin: %v", err)
		}
		line := h52ReadCompletion(t, fifo, 10*time.Second)
		_ = cmd.Wait()
		var term h52TerminalRecord
		if err := json.Unmarshal([]byte(line), &term); err != nil {
			t.Fatalf("terminal record is not JSON: %v (%q)", err, line)
		}
		if term.Event != "end" {
			t.Fatalf("terminal record event=%q, want end", term.Event)
		}
		if term.Calls != 1 {
			t.Fatalf("terminal record calls=%d, want 1", term.Calls)
		}
		raw, err := os.ReadFile(artifact)
		if err != nil {
			t.Fatalf("read artifact: %v", err)
		}
		prefix, endLine := h52ArtifactPrefix(raw)
		if string(endLine) != line {
			t.Fatalf("artifact end line %q != fifo %q", endLine, line)
		}
		if term.Bytes != len(prefix) {
			t.Fatalf("end.bytes=%d, prefix len=%d", term.Bytes, len(prefix))
		}
		if want := h52SHA256(prefix); term.SHA256 != want {
			t.Fatalf("end.sha256=%s, prefix sha256=%s", term.SHA256, want)
		}
	})

	t.Run("observer_stdin_left_open_has_no_terminal_record", func(t *testing.T) {
		stdin, fifo, _, _ := h52StartObserverProcess(t, backend, "observer-open")
		t.Cleanup(func() { _ = stdin })
		line, err := h52TryReadCompletion(fifo, 500*time.Millisecond)
		if err == nil {
			t.Fatalf("observer emitted a terminal record with stdin still open: %q", line)
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected read deadline exceeded with stdin open, got %v", err)
		}
	})

	t.Run("observer_unparsable_line_writes_observer_error", func(t *testing.T) {
		stdin, fifo, artifact, cmd := h52StartObserverProcess(t, backend, "observer-bad-line")
		if _, err := io.WriteString(stdin, "not-a-json-object\n"); err != nil {
			t.Fatalf("write unparsable line: %v", err)
		}
		if err := stdin.Close(); err != nil {
			t.Fatalf("close observer stdin: %v", err)
		}
		line := h52ReadCompletion(t, fifo, 10*time.Second)
		_ = cmd.Wait()
		var term h52TerminalRecord
		if err := json.Unmarshal([]byte(line), &term); err != nil {
			t.Fatalf("terminal record is not JSON: %v (%q)", err, line)
		}
		if term.Event != "observer_error" {
			t.Fatalf("terminal record event=%q, want observer_error", term.Event)
		}
		raw, err := os.ReadFile(artifact)
		if err != nil {
			t.Fatalf("read artifact: %v", err)
		}
		if bytes.Contains(raw, []byte(`"event":"end"`)) {
			t.Fatalf("artifact contains an end record after observer_error: %s", raw)
		}
	})

	t.Run("deny_against_complete_session_that_contains_the_id", func(t *testing.T) {
		res := h52ObserverSession(t, backend, "deny-leak", []string{
			`{"jsonrpc":"2.0","id":"txn-deny-leak","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/out.txt"}}}`,
		})
		wantReceived := false
		rec, err := h52DecideBackendReceipt(res, "txn-deny-leak", &wantReceived)
		if rec == nil {
			t.Fatal("decision said the call was not received; the session contains the id")
		}
		if err == nil {
			t.Fatal("deny judgement passed against a complete session that contains the id")
		}
		if !strings.Contains(err.Error(), "the backend received a call the gate denied:") {
			t.Fatalf("named leak missing: %v", err)
		}
	})

	t.Run("forwarded_against_complete_zero_call_session", func(t *testing.T) {
		res := h52ObserverSession(t, backend, "forward-empty", nil)
		res.sentCallIDs = []string{"txn-forward-empty"}
		wantReceived := true
		rec, err := h52DecideBackendReceipt(res, "txn-forward-empty", &wantReceived)
		if rec != nil {
			t.Fatal("validator minted a receive from a zero-call session")
		}
		if err == nil {
			t.Fatal("forwarded judgement passed against a complete zero-call session")
		}
		if !strings.Contains(err.Error(), "the expected call never reached the backend (session calls=0)") {
			t.Fatalf("named missing-receive missing: %v", err)
		}
	})

	visor := buildVisor(t)

	t.Run("stdout_pipe_parent_is_unknown_not_a_deny_pass", func(t *testing.T) {
		err := h52StdoutPipeParentUnknown(t, visor, backend)
		if err == nil {
			t.Fatal("parent using StdoutPipe produced a deny pass")
		}
		if !strings.Contains(err.Error(), "H52 UNKNOWN:") {
			t.Fatalf("want UNKNOWN, got %v", err)
		}
		if strings.Contains(err.Error(), "the backend received a call the gate denied:") {
			t.Fatalf("StdoutPipe parent must not fail as a named leak: %v", err)
		}
	})

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
				"path":                   "/tmp/out.txt",
				"_verified_actor":        map[string]any{"principal_id": "attacker", "scopes": []string{"read", "write"}},
				"verified_actor":         "attacker",
				"verified_actor_context": map[string]any{"principal_id": "attacker", "scopes": []string{"read", "write"}},
			},
		})
		h52RequireDenied(t, res, "txn-fake-identity", "verified actor context required")
	})

	t.Run("caller_supplied_identity_is_stripped_before_relay", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "strip-identity", policy: h52PolicyIdentityRequired,
			actor: h52Actor(t, nil),
			arguments: map[string]any{
				"path":                   "/tmp/out.txt",
				"_verified_actor":        map[string]any{"principal_id": "attacker"},
				"verified_actor":         "attacker",
				"verified_actor_context": map[string]any{"principal_id": "attacker", "scopes": []string{"read", "write"}},
			},
		})
		rec := h52RequireForwarded(t, res, "txn-strip-identity")
		// Every alias is carried in the client request above, so a surviving alias
		// changes the raw argument bytes the backend received. The expectation is
		// the literal byte string the proxy relays for the stripped object, so an
		// extra, missing or renamed key all fail here.
		const wantRawArgs = `{"path":"/tmp/out.txt"}`
		want := h52SHA256([]byte(wantRawArgs))
		if rec.ArgsSHA256 != want {
			t.Fatalf("the backend received arguments that still carry caller-supplied identity: got %s, want sha256 of %s", rec.ArgsSHA256, wantRawArgs)
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
		// The grant is timed against this actor's own expiry. Headroom keeps
		// the context live long enough to reach the approval gate; granting
		// after expiresAt is scenario construction, not deny synchronisation.
		expiresAt := time.Now().UTC().Add(8 * time.Second)
		res := runIdentityHarness(t, visor, backend, h52Options{
			name:             "approval-expiry",
			policy:           h52PolicyApprovalRequired,
			actor:            h52Actor(t, func(c *actorcontext.Context) { c.ExpiresAt = expiresAt }),
			arguments:        map[string]any{"path": "/tmp/out.txt"},
			expiresAt:        expiresAt,
			grantAfterExpiry: true,
		})
		h52RequireDenied(t, res, "txn-approval-expiry", "expired")
		msg := h52DenyMessage(t, res, "txn-approval-expiry")
		if strings.Contains(msg, "timeout") {
			t.Fatalf("%s: denial names an approval timeout rather than expiry: %q", res.name, msg)
		}
	})

	t.Run("multiple_audiences_where_exactly_one_is_required", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "multi-audience", policy: h52PolicyIdentityRequired,
			actor:     h52MultiAudienceActor(t),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		h52RequireStartupRefusal(t, res, "audience")
	})

	// H52 gap probe, not an acceptance case: the decision path does not check the
	// context audience, so a wrong audience is measured as forwarded rather than
	// denied. The measurement must come from the artifact: only a record proves the
	// call was forwarded, and only a denial response with no record proves the gap
	// closed. An unreadable artifact or a visor that never served leaves the
	// question unanswered, so it must never print the closed message.
	t.Run("gap_probe_wrong_audience_is_not_enforced", func(t *testing.T) {
		res := runIdentityHarness(t, visor, backend, h52Options{
			name: "audience-gap", policy: h52PolicyIdentityRequired,
			actor:     h52Actor(t, func(c *actorcontext.Context) { c.Audience = "https://attacker.example.test" }),
			arguments: map[string]any{"path": "/tmp/out.txt"},
		})
		if res.exited {
			t.Fatalf("%s: visor exited (code %d) instead of serving; the audience gap is unmeasured; stderr: %s", res.name, res.exitCode, res.stderr)
		}
		rec := h52GapReceipt(t, res, "txn-audience-gap")
		if rec == nil {
			h52RequireClientCardinality(t, res, "txn-audience-gap", false)
			msg := h52DenyMessage(t, res, "txn-audience-gap")
			t.Logf("H52 GAP CLOSED: the observer recorded no call for txn-audience-gap and the gate denied it (%q); update harness/invariants.md H52 and delete the gap note", msg)
			return
		}
		h52RequireClientCardinality(t, res, "txn-audience-gap", true)
		t.Logf("H52 GAP: audience is not enforced in the decision path; the observer recorded transaction %s, tool %s, received %s for a context with audience %q. Enforcement is a separate security-classified change.", rec.Transaction, rec.Tool, rec.ReceivedAt, "https://attacker.example.test")
	})
}
