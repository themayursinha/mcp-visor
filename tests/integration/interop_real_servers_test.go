//go:build interop

// Package main_test: real MCP interoperability matrix (Phase 1).
//
// These tests run REAL MCP reference servers through mcp-visor and assert
// allow/deny/taint/audit behavior at the proxy boundary. They are the
// non-mock counterpart to the demo-mock integration tests.
//
// Client path A (this file): raw JSON-RPC 2.0 over stdio, spoken directly to
// the mcp-visor binary (same framing style as proxy_integration_test.go).
// Client path B: tests/interop/python_sdk_client.py — the official Python MCP
// SDK driving the same proxied server over stdio.
//
// Servers (pinned 2026-08-03):
//   - filesystem: npx -y @modelcontextprotocol/server-filesystem@2026.7.10 <sandbox>
//   - fetch:      uvx --with mcp==1.26.0 mcp-server-fetch@2026.7.10
//
// Run (tools must be on PATH; npx/uvx fetch packages on first run):
//
//	go test -tags interop ./tests/integration/ -run 'TestInterop' -v -count=1
//
// The tests skip (not fail) when npx or uvx is unavailable, so the default
// `go test ./...` gate stays hermetic.
package main_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fsServerPkg = "@modelcontextprotocol/server-filesystem@2026.7.10"
	fetchServer = "mcp-server-fetch@2026.7.10"
	fetchSDKPin = "mcp==1.26.0"
)

func haveTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// setupSandbox creates /tmp/interop-sandbox with benign and sensitive files,
// matching the public reproduce recipe in docs/interoperability.md.
func setupSandbox(t *testing.T) string {
	t.Helper()
	root := "/tmp/interop-sandbox"
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("clean sandbox: %v", err)
	}
	dirs := []string{filepath.Join(root, "docs"), filepath.Join(root, "secrets")}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	files := map[string]string{
		filepath.Join(root, "docs", "readme.txt"):              "hello world\n",
		filepath.Join(root, "secrets", "customer-secrets.env"): "password=super-secret-value\n",
		filepath.Join(root, "secrets", "creds.txt"):            "SK-" + strings.Repeat("A", 48) + "\n",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

// interopInit performs initialize + notifications/initialized over the pipe.
func interopInit(t *testing.T, w *bufio.Writer, r *bufio.Reader) {
	t.Helper()
	initMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "interop-client-a", "version": "1.0.0"},
		},
	}
	if err := sendMessage(w, initMsg); err != nil {
		t.Fatalf("send initialize: %v", err)
	}
	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read initialize response: %v", err)
	}
	if resp["result"] == nil {
		t.Fatalf("initialize failed: %v", resp)
	}
	if err := sendMessage(w, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatalf("send initialized: %v", err)
	}
}

// interopListTools returns the tool name list from tools/list.
func interopListTools(t *testing.T, w *bufio.Writer, r *bufio.Reader) []string {
	t.Helper()
	if err := sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}}); err != nil {
		t.Fatalf("send tools/list: %v", err)
	}
	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read tools/list: %v", err)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list result missing: %v", resp)
	}
	var names []string
	for _, item := range result["tools"].([]any) {
		tool := item.(map[string]any)
		names = append(names, tool["name"].(string))
	}
	return names
}

// interopCall performs a tools/call and returns (response map, isError).
func interopCall(t *testing.T, w *bufio.Writer, r *bufio.Reader, id int, name string, args map[string]any) map[string]any {
	t.Helper()
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": args},
	}
	if err := sendMessage(w, msg); err != nil {
		t.Fatalf("send tools/call %s: %v", name, err)
	}
	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read tools/call %s response: %v", name, err)
	}
	if resp["error"] != nil {
		return resp
	}
	return resp
}

// readAuditEvents loads JSONL audit events written to the temp audit log for
// the most recently started visor process in this test.
func readAuditEvents(t *testing.T, auditPath string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line: %v", err)
		}
		events = append(events, e)
	}
	return events
}

func TestInteropFilesystemStdio(t *testing.T) {
	if !haveTool("npx") {
		t.Skip("npx not available; skipping real filesystem interop test")
	}
	sandbox := setupSandbox(t)
	policyPath := filepath.Join("..", "..", "examples", "policies", "interop", "filesystem-sandbox.yaml")
	// Policy pins the sandbox root; verify it matches what the test builds.
	if !strings.Contains(readFileString(t, policyPath), "/tmp/interop-sandbox") {
		t.Fatalf("policy %s does not reference the sandbox root", policyPath)
	}

	visor := buildVisor(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(visor, "serve",
		"-server", "npx", "-server-arg", "-y", "-server-arg", fsServerPkg, "-server-arg", sandbox,
		"-server-name", "filesystem", "-policy", policyPath, "-audit-log", auditPath,
	)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			t.Logf("visor stderr: %s", sc.Text())
		}
	}()

	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	interopInit(t, w, r)
	names := interopListTools(t, w, r)
	joined := strings.Join(names, ",")
	for _, want := range []string{"read_file", "read_text_file", "write_file", "list_directory"} {
		if !strings.Contains(joined, want) {
			t.Errorf("real filesystem server tools missing %q (got %d tools)", want, len(names))
		}
	}

	// S1: benign read allowed and reaches the server.
	resp := interopCall(t, w, r, 100, "read_file", map[string]any{"path": filepath.Join(sandbox, "docs", "readme.txt")})
	if resp["error"] != nil {
		t.Fatalf("benign read_file denied: %v", resp["error"])
	}
	// S1: deny — read outside the sandbox root must be denied by policy.
	resp = interopCall(t, w, r, 101, "read_file", map[string]any{"path": "/etc/hostname"})
	if resp["error"] == nil {
		t.Fatal("read_file /etc/hostname was allowed; allow_path rule must deny outside sandbox")
	}

	// Audit: allow + deny records exist with the right decisions.
	time.Sleep(200 * time.Millisecond)
	events := readAuditEvents(t, auditPath)
	var allowed, denied int
	for _, e := range events {
		if e["event_type"] == "tool_call_allowed" && e["tool"] == "read_file" {
			allowed++
		}
		if e["event_type"] == "tool_call_denied" && e["tool"] == "read_file" {
			denied++
		}
	}
	if allowed < 1 {
		t.Errorf("audit missing tool_call_allowed for read_file: %d", allowed)
	}
	if denied < 1 {
		t.Errorf("audit missing tool_call_denied for read_file: %d", denied)
	}
}

func TestInteropFilesystemTaintEgress(t *testing.T) {
	if !haveTool("npx") {
		t.Skip("npx not available; skipping real filesystem taint/egress interop test")
	}
	sandbox := setupSandbox(t)
	policyPath := filepath.Join("..", "..", "examples", "policies", "interop", "filesystem-sandbox.yaml")

	visor := buildVisor(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(visor, "serve",
		"-server", "npx", "-server-arg", "-y", "-server-arg", fsServerPkg, "-server-arg", sandbox,
		"-server-name", "filesystem", "-policy", policyPath, "-audit-log", auditPath,
	)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			t.Logf("visor stderr: %s", sc.Text())
		}
	}()
	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	interopInit(t, w, r)

	// Benign read first: no taint expected.
	resp := interopCall(t, w, r, 200, "read_file", map[string]any{"path": filepath.Join(sandbox, "docs", "readme.txt")})
	if resp["error"] != nil {
		t.Fatalf("benign read denied: %v", resp["error"])
	}

	// Sensitive read: allowed by policy but must taint the session.
	resp = interopCall(t, w, r, 201, "read_file", map[string]any{"path": filepath.Join(sandbox, "secrets", "customer-secrets.env")})
	if resp["error"] != nil {
		t.Fatalf("sensitive read denied: %v", resp["error"])
	}

	// Egress-shaped call in the tainted session must be denied BEFORE server
	// execution. This session proxies only the real filesystem server, so the
	// registered egress sink is write_file (a file-exfil shaped action), not
	// fetch — the CLI proxies one server per `serve` process, so the
	// filesystem→fetch pair cannot be formed in a single session. The fetch
	// sink cell is covered by TestInteropFetchStdio.
	resp = interopCall(t, w, r, 202, "write_file", map[string]any{
		"path":    filepath.Join(sandbox, "exfil.txt"),
		"content": "customer secrets",
	})
	if resp["error"] == nil {
		t.Fatal("write_file after sensitive read was allowed; egress control must deny")
	}

	time.Sleep(200 * time.Millisecond)
	events := readAuditEvents(t, auditPath)
	var sawTaint, sawEgressDeny bool
	for _, e := range events {
		if e["event_type"] == "session_tainted" {
			sawTaint = true
			if taints, _ := e["session_taints"].([]any); len(taints) == 0 {
				t.Errorf("session_tainted event has no session_taints: %v", e)
			}
		}
		if e["event_type"] == "tool_call_denied" && e["tool"] == "write_file" {
			sawEgressDeny = true
			if e["policy_rule"] != "block_egress_after_sensitive_read" {
				t.Errorf("write_file deny did not cite egress control: %v", e["policy_rule"])
			}
			if e["taint_source"] == "" || e["taint_reason"] == "" {
				t.Errorf("write_file deny missing taint_source/taint_reason: %v", e)
			}
		}
	}
	if !sawTaint {
		t.Error("audit missing session_tainted event after sensitive read")
	}
	if !sawEgressDeny {
		t.Error("audit missing egress deny event for write_file")
	}
}

func TestInteropFetchStdio(t *testing.T) {
	if !haveTool("uvx") {
		t.Skip("uvx not available; skipping real fetch interop test")
	}
	policyPath := filepath.Join("..", "..", "examples", "policies", "interop", "fetch-egress.yaml")

	// Local HTTP sink (no public internet).
	srv := startLocalHTTPSink(t)
	allowURL := fmt.Sprintf("http://%s/hello", srv.addr)
	secretURL := fmt.Sprintf("http://%s/secrets/creds", srv.addr)

	visor := buildVisor(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(visor, "serve",
		"-server", "uvx", "-server-arg", "--with", "-server-arg", fetchSDKPin, "-server-arg", fetchServer,
		"-server-name", "fetch", "-policy", policyPath, "-audit-log", auditPath,
	)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			t.Logf("visor stderr: %s", sc.Text())
		}
	}()
	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	interopInit(t, w, r)
	names := interopListTools(t, w, r)
	if len(names) != 1 || names[0] != "fetch" {
		t.Fatalf("expected real fetch server to expose only 'fetch', got %v", names)
	}

	// S2: benign fetch allowed.
	resp := interopCall(t, w, r, 300, "fetch", map[string]any{"url": allowURL})
	if resp["error"] != nil {
		t.Fatalf("benign fetch denied: %v", resp["error"])
	}

	// S2 deny: unregistered tool must be denied by default_action: deny.
	resp = interopCall(t, w, r, 301, "http_post", map[string]any{"url": allowURL})
	if resp["error"] == nil {
		t.Fatal("http_post was allowed; default_action deny must block unregistered tools")
	}

	// S3: fetch a sensitive URL — allowed but taints; next fetch must be denied.
	resp = interopCall(t, w, r, 302, "fetch", map[string]any{"url": secretURL})
	if resp["error"] != nil {
		t.Fatalf("sensitive fetch denied (should allow+taint): %v", resp["error"])
	}
	resp = interopCall(t, w, r, 303, "fetch", map[string]any{"url": allowURL})
	if resp["error"] == nil {
		t.Fatal("fetch after sensitive fetch was allowed; egress control must deny")
	}

	time.Sleep(200 * time.Millisecond)
	events := readAuditEvents(t, auditPath)
	var sawTaint, sawEgressDeny bool
	for _, e := range events {
		if e["event_type"] == "session_tainted" && e["tool"] == "fetch" {
			sawTaint = true
		}
		if e["event_type"] == "tool_call_denied" && e["tool"] == "fetch" {
			sawEgressDeny = true
			if e["policy_rule"] != "block_fetch_after_sensitive_fetch" {
				t.Errorf("fetch deny did not cite egress control: %v", e["policy_rule"])
			}
		}
	}
	if !sawTaint {
		t.Error("audit missing session_tainted event after sensitive fetch")
	}
	if !sawEgressDeny {
		t.Error("audit missing egress deny event for second fetch")
	}
}

// localHTTPSink is a minimal loopback HTTP server used as the fetch target.
type localHTTPSink struct {
	addr string
	mu   sync.Mutex
	hits []string
}

func (s *localHTTPSink) serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.URL.Path)
		s.mu.Unlock()
		_, _ = fmt.Fprintf(w, "ok from %s", r.URL.Path)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s.addr = ln.Addr().String()
	go func() { _ = http.Serve(ln, mux) }()
}

func startLocalHTTPSink(t *testing.T) *localHTTPSink {
	t.Helper()
	s := &localHTTPSink{}
	s.serve()
	t.Cleanup(func() {})
	return s
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// TestInteropRemotePostHandshake proves the shared enforcement gate on the
// remote HTTP+SSE path with a local loopback SSE mock (no third-party hosted
// remote, no tokens). Cells:
//
//   - initialize handshake completes over HTTP+SSE
//   - tools/list relays the remote server's tool list
//   - allowed tools/call reaches the remote server (mock records it)
//   - unregistered tools/call is denied BEFORE relay (mock does not see it)
//   - audit log records allow + deny with the proxy as the decision point
func TestInteropRemotePostHandshake(t *testing.T) {
	received := make(chan string, 32)
	mock := newInteropSSEMock(t, received)

	policyPath := filepath.Join("..", "..", "examples", "policies", "interop", "remote-mock.yaml")
	visor := buildVisor(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(visor, "serve",
		"-server-url", "http://"+mock.addr,
		"-server-name", "mock-remote", "-policy", policyPath, "-audit-log", auditPath,
	)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			t.Logf("visor stderr: %s", sc.Text())
		}
	}()
	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)

	interopInit(t, w, r)

	names := interopListTools(t, w, r)
	joined := strings.Join(names, ",")
	for _, want := range []string{"fetch", "read_file"} {
		if !strings.Contains(joined, want) {
			t.Errorf("remote mock tools missing %q (got %d tools)", want, len(names))
		}
	}

	// Allowed fetch call must reach the remote mock server.
	resp := interopCall(t, w, r, 400, "fetch", map[string]any{"url": "http://127.0.0.1/hello"})
	if resp["error"] != nil {
		t.Fatalf("allowed remote fetch denied: %v", resp["error"])
	}

	// Unregistered tool must be denied at the proxy BEFORE relay.
	resp = interopCall(t, w, r, 401, "http_post", map[string]any{"url": "http://127.0.0.1/hello"})
	if resp["error"] == nil {
		t.Fatal("http_post was allowed; default_action deny must block unregistered tools on remote path")
	}

	time.Sleep(200 * time.Millisecond)
	var sawAllow, sawDeny bool
	for _, e := range readAuditEvents(t, auditPath) {
		if e["event_type"] == "tool_call_allowed" && e["tool"] == "fetch" && e["server"] == "mock-remote" {
			sawAllow = true
		}
		if e["event_type"] == "tool_call_denied" && e["tool"] == "http_post" && e["server"] == "mock-remote" {
			sawDeny = true
		}
	}
	if !sawAllow {
		t.Error("audit missing tool_call_allowed for remote fetch")
	}
	if !sawDeny {
		t.Error("audit missing tool_call_denied for remote http_post")
	}

	// The mock must have seen exactly one tools/call (fetch), never http_post.
	select {
	case name := <-received:
		if name != "fetch" {
			t.Errorf("remote mock received unexpected tools/call: %s", name)
		}
	case <-time.After(2 * time.Second):
		t.Error("remote mock never received the allowed fetch tools/call")
	}
	select {
	case name := <-received:
		t.Errorf("remote mock received denied tools/call %s; must be blocked at proxy", name)
	case <-time.After(500 * time.Millisecond):
		// expected: no second call reached the mock
	}
}

// interopSSEMock is a minimal local HTTP+SSE server that completes the MCP
// handshake and responds to tools/list and tools/call over SSE, recording each
// tools/call tool name on the received channel.
//
// Framing matches internal/transport/http.go: the proxy keeps one GET /sse
// stream open and POSTs requests to /message; responses arrive as SSE events on
// that same stream. The /message handler therefore pushes the response payload
// into a channel that the /sse handler drains and writes with `data: ` framing.
type interopSSEMock struct {
	addr string
}

func newInteropSSEMock(t *testing.T, received chan<- string) *interopSSEMock {
	t.Helper()
	s := &interopSSEMock{}
	responses := make(chan string, 32)

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		flusher.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case payload := <-responses:
				_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
				flusher.Flush()
			}
		}
	})
	mux.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var msg map[string]any
		if err := json.Unmarshal(body, &msg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		method, _ := msg["method"].(string)
		id, _ := msg["id"].(float64)
		switch method {
		case "initialize":
			responses <- fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"mock-remote","version":"1.0"},"capabilities":{"tools":{"listChanged":false}}}}`, id)
		case "tools/list":
			responses <- fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"result":{"tools":[{"name":"fetch","description":"fetch url","inputSchema":{"type":"object","properties":{"url":{"type":"string"}}}},{"name":"read_file","description":"read file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}}`, id)
		case "tools/call":
			if params, ok := msg["params"].(map[string]any); ok {
				name, _ := params["name"].(string)
				select {
				case received <- name:
				default:
				}
			}
			responses <- fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"ok from mock remote"}]}}`, id)
		default:
			// notifications and other methods: no response needed
		}
		w.WriteHeader(http.StatusAccepted)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.addr = ln.Addr().String()
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}
