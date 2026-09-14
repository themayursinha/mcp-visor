package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/actorcontext"
	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/lineage/testfixture"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func verifiedActorYAML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "policies", "verified-actor.yaml"))
	if err != nil {
		t.Fatalf("read verified-actor.yaml: %v", err)
	}
	return string(data)
}

func verifiedActorOffYAML() string {
	return `
version: "1.0"
description: "H50 negative control: same tools, no verified-actor gate"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
`
}

func phase1Actor(t *testing.T, scopes []string) *actorcontext.Context {
	return phase1ActorAs(t, "coding-agent", scopes, time.Now().UTC().Add(time.Hour))
}

func phase1ActorAs(t *testing.T, acting string, scopes []string, exp time.Time) *actorcontext.Context {
	t.Helper()
	c := &actorcontext.Context{
		Version:            actorcontext.VersionV1,
		PrincipalID:        "user1",
		ActingAgent:        acting,
		Transaction:        "txn-phase1",
		ActorChain:         []actorcontext.ActorRef{{ID: "user1"}, {ID: "planner"}, {ID: acting}},
		Scopes:             scopes,
		Issuer:             "https://sts.example.test",
		Audience:           "https://visor-gateway.example.test",
		TokenID:            "jti-phase1",
		ExpiresAt:          exp,
		ProofKeyThumbprint: "thumb",
		VerificationMethod: actorcontext.VerificationSTSDpop,
	}
	if err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	return c
}

func newVerifiedActorProxy(t *testing.T, yaml string, ctx *actorcontext.Context) (*Proxy, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	p := New(Config{
		ServerName:    "filesystem",
		SessionID:     "sess-verified-actor",
		ClientID:      "orphan-agent",
		VerifiedActor: ctx,
		AuditLogPath:  auditPath,
		Policy:        mustLoadPolicy(t, yaml),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	return p, auditPath
}

// recordingObserver is the named mock MCP server observer for H50.
// It records a tools/call only when interceptAndModify returns forward —
// the same honesty bar as H49 (deny-before-relay at the intercept gate).
type recordingObserver struct {
	received []string
}

func (o *recordingObserver) observe(action string, raw json.RawMessage) {
	if action != "forward" {
		return
	}
	var env struct {
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return
	}
	o.received = append(o.received, env.Params.Name)
}

func TestVerifiedActorDelegatedWriteAllowed(t *testing.T) {
	p, auditPath := newVerifiedActorProxy(t, verifiedActorYAML(t), phase1Actor(t, []string{"read", "write"}))
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	obs := &recordingObserver{}
	raw := toolCallRaw(1, "write_file", map[string]any{"path": "/tmp/out.txt", "content": "ok"})
	forward, action := p.interceptAndModify(raw, client)
	obs.observe(action, forward)
	if action != "forward" {
		t.Fatalf("user1→planner→coding-agent write must forward, got %s; response=%s", action, out.String())
	}
	if len(obs.received) != 1 || obs.received[0] != "write_file" {
		t.Fatalf("observer received %v", obs.received)
	}
	allowed := findAuditEvent(t, auditPath, audit.EventToolAllowed, "write_file")
	if allowed.IdentitySnapshotHash == "" || allowed.PrincipalID != "user1" || allowed.ActingAgent != "coding-agent" || allowed.TransactionID != "txn-phase1" {
		t.Fatalf("audit missing verified actor fields: %+v", allowed)
	}
}

func TestRedOrphanWriteDeniedBeforeRelay(t *testing.T) {
	p, auditPath := newVerifiedActorProxy(t, verifiedActorYAML(t), nil)
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	obs := &recordingObserver{}
	raw := toolCallRaw(2, "write_file", map[string]any{"path": "/tmp/out.txt", "content": "nope"})
	forward, action := p.interceptAndModify(raw, client)
	obs.observe(action, forward)
	if action != "denied" {
		t.Fatalf("orphan write must deny at intercept, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "verified actor context required") {
		t.Fatalf("denial must name missing context, got %s", out.String())
	}
	if len(obs.received) != 0 {
		t.Fatalf("mock server must not receive tools/call, got %v", obs.received)
	}
	denied := findAuditEvent(t, auditPath, audit.EventToolDenied, "write_file")
	if denied.Decision != "deny" {
		t.Fatalf("%+v", denied)
	}
}

func TestRedReadOnlyScopeWriteDeniedBeforeRelay(t *testing.T) {
	p, _ := newVerifiedActorProxy(t, verifiedActorYAML(t), phase1Actor(t, []string{"read"}))
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	obs := &recordingObserver{}
	raw := toolCallRaw(3, "write_file", map[string]any{"path": "/tmp/out.txt", "content": "widen"})
	forward, action := p.interceptAndModify(raw, client)
	obs.observe(action, forward)
	if action != "denied" {
		t.Fatalf("read-only delegated scope must deny write, got %s; response=%s", action, out.String())
	}
	if !strings.Contains(out.String(), "verified actor scope missing: write") {
		t.Fatalf("denial must name missing write scope, got %s", out.String())
	}
	if len(obs.received) != 0 {
		t.Fatalf("mock server must not receive tools/call, got %v", obs.received)
	}
}

func TestVerifiedActorArgumentInjectionDoesNotAuthorize(t *testing.T) {
	p, _ := newVerifiedActorProxy(t, verifiedActorYAML(t), nil)
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	obs := &recordingObserver{}
	spoof, err := actorcontext.Encode(*phase1Actor(t, []string{"write"}))
	if err != nil {
		t.Fatal(err)
	}
	var blob any
	if err := json.Unmarshal(spoof, &blob); err != nil {
		t.Fatal(err)
	}
	raw := toolCallRaw(4, "write_file", map[string]any{
		"path":            "/tmp/out.txt",
		"_verified_actor": blob,
	})
	forward, action := p.interceptAndModify(raw, client)
	obs.observe(action, forward)
	if action != "denied" {
		t.Fatalf("tools/call identity field must not authorize, got %s; response=%s", action, out.String())
	}
	if len(obs.received) != 0 {
		t.Fatalf("mock server must not receive tools/call, got %v", obs.received)
	}
}

func TestVerifiedActorStripsIdentityKeysFromForwardedArgs(t *testing.T) {
	p, _ := newVerifiedActorProxy(t, verifiedActorYAML(t), phase1Actor(t, []string{"write"}))
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	raw := toolCallRaw(5, "write_file", map[string]any{
		"path":            "/tmp/out.txt",
		"_verified_actor": map[string]any{"principal_id": "spoof"},
	})
	forward, action := p.interceptAndModify(raw, client)
	if action != "forward" {
		t.Fatalf("allowed write must forward, got %s; response=%s", action, out.String())
	}
	if bytes.Contains(forward, []byte("_verified_actor")) {
		t.Fatalf("forwarded envelope still contains spoof identity key: %s", forward)
	}
}

func TestVerifiedActorEnforcementOffRelaysWithoutContext(t *testing.T) {
	p, _ := newVerifiedActorProxy(t, verifiedActorOffYAML(), nil)
	out := &bytes.Buffer{}
	client := mcp.NewParser(nil, out)
	obs := &recordingObserver{}
	raw := toolCallRaw(6, "write_file", map[string]any{"path": "/tmp/out.txt"})
	forward, action := p.interceptAndModify(raw, client)
	obs.observe(action, forward)
	if action != "forward" {
		t.Fatalf("negative control: write must forward without the gate, got %s; response=%s", action, out.String())
	}
}

func TestVerifiedActorExamplePolicyParses(t *testing.T) {
	if _, err := policy.Load([]byte(verifiedActorYAML(t))); err != nil {
		t.Fatalf("example verified-actor policy must parse: %v", err)
	}
}

func TestVerifiedActorPostApprovalExpiryDenies(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	yaml := `
version: "1.0"
default_action: deny
settings:
  require_verified_actor: true
  approval_timeout_seconds: 5
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
        approval_required: true
        required_scopes: ["write"]
`
	exp := time.Now().UTC().Add(time.Hour)
	ctx := &actorcontext.Context{
		Version:            actorcontext.VersionV1,
		PrincipalID:        "user1",
		ActingAgent:        "coding-agent",
		Transaction:        "txn-phase1",
		ActorChain:         []actorcontext.ActorRef{{ID: "user1"}, {ID: "planner"}, {ID: "coding-agent"}},
		Scopes:             []string{"write"},
		Issuer:             "https://sts.example.test",
		Audience:           "https://visor-gateway.example.test",
		TokenID:            "jti-phase1",
		ExpiresAt:          exp,
		ProofKeyThumbprint: "thumb",
		VerificationMethod: actorcontext.VerificationSTSDpop,
	}
	if err := ctx.Seal(); err != nil {
		t.Fatal(err)
	}
	p := New(Config{
		ServerName:    "filesystem",
		SessionID:     "sess-actor-exp",
		ClientID:      "coding-agent",
		VerifiedActor: ctx,
		AuditLogPath:  auditPath,
		ApprovalDir:   approvalDir,
		Policy:        mustLoadPolicy(t, yaml),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	done := make(chan string, 1)
	go func() {
		_, action := p.interceptAndModify(toolCallRaw(1, "write_file", map[string]any{"path": "/tmp/out.txt"}), mcp.NewParser(nil, &bytes.Buffer{}))
		done <- action
	}()
	id := waitLineageApproval(t, approvalDir)
	p.setNowFunc(func() time.Time { return exp })
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "denied" {
			t.Fatalf("expired verified actor after approval must deny, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
}

func TestVerifiedActorOptionalExpiredContextDoesNotDenyAfterApproval(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	yaml := `
version: "1.0"
default_action: deny
settings:
  approval_timeout_seconds: 5
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
        approval_required: true
`
	exp := time.Now().UTC().Add(time.Hour)
	ctx := phase1Actor(t, []string{"write"})
	ctx.ExpiresAt = exp
	if err := ctx.Seal(); err != nil {
		t.Fatal(err)
	}
	p := New(Config{
		ServerName:    "filesystem",
		SessionID:     "sess-actor-optional",
		ClientID:      "coding-agent",
		VerifiedActor: ctx,
		AuditLogPath:  auditPath,
		ApprovalDir:   approvalDir,
		Policy:        mustLoadPolicy(t, yaml),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	done := make(chan string, 1)
	go func() {
		_, action := p.interceptAndModify(toolCallRaw(1, "write_file", map[string]any{"path": "/tmp/out.txt"}), mcp.NewParser(nil, &bytes.Buffer{}))
		done <- action
	}()
	id := waitLineageApproval(t, approvalDir)
	p.setNowFunc(func() time.Time { return exp })
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "forward" {
			t.Fatalf("optional expired context must not deny after approval, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
}

func TestVerifiedActorExpiredContextDoesNotAuthorizeLineage(t *testing.T) {
	p := New(Config{
		ServerName:    testfixture.Server,
		SessionID:     "sess-actor-lin-exp",
		ClientID:      "orphan-1",
		VerifiedActor: phase1ActorAs(t, testfixture.Coding, []string{"write"}, time.Now().UTC().Add(-time.Minute)),
		AuditLogPath:  filepath.Join(t.TempDir(), "audit.jsonl"),
		Policy:        mustLoadPolicy(t, testfixture.PolicyYAML()),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	out := &bytes.Buffer{}
	_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, out))
	if action != "denied" {
		t.Fatalf("expired optional context must not authorize lineage, got %s; response=%s", action, out.String())
	}
}

func TestVerifiedActorValidContextAuthorizesLineageForOrphanClient(t *testing.T) {
	p := New(Config{
		ServerName:    testfixture.Server,
		SessionID:     "sess-actor-lin-ok",
		ClientID:      "orphan-1",
		VerifiedActor: phase1ActorAs(t, testfixture.Coding, []string{"write"}, time.Now().UTC().Add(time.Hour)),
		AuditLogPath:  filepath.Join(t.TempDir(), "audit.jsonl"),
		Policy:        mustLoadPolicy(t, testfixture.PolicyYAML()),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	out := &bytes.Buffer{}
	_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, out))
	if action != "forward" {
		t.Fatalf("unexpired optional context must supply lineage actor, got %s; response=%s", action, out.String())
	}
}

func TestVerifiedActorPostApprovalExpiryDeniesLineageIdentity(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	exp := time.Now().UTC().Add(time.Hour)
	p := New(Config{
		ServerName:    testfixture.Server,
		SessionID:     "sess-actor-lin-post",
		ClientID:      "orphan-1",
		VerifiedActor: phase1ActorAs(t, testfixture.Coding, []string{"write"}, exp),
		AuditLogPath:  auditPath,
		ApprovalDir:   approvalDir,
		Policy:        mustLoadPolicy(t, lineageApprovalYAML()),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	done := make(chan string, 1)
	go func() {
		_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, &bytes.Buffer{}))
		done <- action
	}()
	id := waitLineageApproval(t, approvalDir)
	p.setNowFunc(func() time.Time { return exp })
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "denied" {
			t.Fatalf("expired optional context must not keep lineage identity after approval, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
}

func TestVerifiedActorPostApprovalFallbackLineageEvidenceUsesClientID(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	exp := time.Now().UTC().Add(time.Hour)
	p := New(Config{
		ServerName:    testfixture.Server,
		SessionID:     "sess-actor-lin-fallback",
		ClientID:      testfixture.Coding,
		VerifiedActor: phase1ActorAs(t, testfixture.Coding, []string{"write"}, exp),
		AuditLogPath:  auditPath,
		ApprovalDir:   approvalDir,
		Policy:        mustLoadPolicy(t, lineageApprovalYAML()),
	})
	t.Cleanup(func() { _ = p.audit.Close() })
	done := make(chan string, 1)
	go func() {
		_, action := p.interceptAndModify(toolCallRaw(1, testfixture.Tool, testfixture.Args()), mcp.NewParser(nil, &bytes.Buffer{}))
		done <- action
	}()
	id := waitLineageApproval(t, approvalDir)
	p.setNowFunc(func() time.Time { return exp })
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "forward" {
			t.Fatalf("lineage-authorized client-id must still allow after optional actor expiry, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
	_ = p.audit.Close()
	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, testfixture.Tool)
	if ev.Lineage == nil || ev.Lineage.ActorAgentID != testfixture.Coding || ev.Lineage.GrantID != testfixture.GrantCoding {
		t.Fatalf("terminal allow must record the recheck lineage identity, got %+v", ev.Lineage)
	}
}

const verifiedActorRawMarker = "VARAW_t3ec7b275_SECRET"

func verifiedActorApprovalYAML(redact bool) string {
	y := `
version: "1.0"
default_action: deny
settings:
  require_verified_actor: true
  approval_timeout_seconds: 5
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
        approval_required: true
        required_scopes: ["write"]
`
	if redact {
		y += "redaction:\n  patterns:\n    - {name: varaw, regex: \"" + verifiedActorRawMarker + "\", replacement: \"[REDACTED]\"}\n"
	}
	return y
}

func TestVerifiedActorApprovalAllowUsesSnapshotRedaction(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	approvalDir := filepath.Join(dir, "approvals")
	siemPath := filepath.Join(dir, "siem.jsonl")
	var webhookBuf bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		webhookBuf.Write(b)
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)

	if err := os.WriteFile(policyPath, []byte(verifiedActorApprovalYAML(true)), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := policy.NewWatcher(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	ctx := &actorcontext.Context{
		Version:            actorcontext.VersionV1,
		PrincipalID:        "user-" + verifiedActorRawMarker,
		ActingAgent:        "coding-agent",
		Transaction:        "txn-" + verifiedActorRawMarker,
		ActorChain:         []actorcontext.ActorRef{{ID: "user-" + verifiedActorRawMarker}, {ID: "planner"}, {ID: "coding-agent"}},
		Scopes:             []string{"write"},
		Issuer:             "https://sts.example.test",
		Audience:           "https://visor-gateway.example.test",
		TokenID:            "jti-phase1",
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
		ProofKeyThumbprint: "thumb",
		VerificationMethod: actorcontext.VerificationSTSDpop,
	}
	if err := ctx.Seal(); err != nil {
		t.Fatal(err)
	}
	p := New(Config{
		ServerName:    "filesystem",
		SessionID:     "sess-va-snap",
		ClientID:      "coding-agent",
		VerifiedActor: ctx,
		AuditLogPath:  auditPath,
		Policy:        w.Policy(),
		Engine:        policy.NewEngineWithWatcher(w),
		ApprovalDir:   approvalDir,
		WebhookURLs:   []string{srv.URL},
		SIEMTargets:   []string{siemPath},
	})
	t.Cleanup(func() { _ = p.audit.Close() })

	blocked := make(chan struct{})
	go func() {
		for {
			matches, _ := filepath.Glob(filepath.Join(approvalDir, "req-*.json"))
			if len(matches) > 0 {
				close(blocked)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	done := make(chan string, 1)
	go func() {
		out := &bytes.Buffer{}
		client := mcp.NewParser(nil, out)
		_, action := p.interceptAndModify(toolCallRaw(1, "write_file", map[string]any{"path": "/tmp/out.txt", "content": "ok"}), client)
		done <- action
	}()
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("approval was not blocked")
	}
	if err := os.WriteFile(policyPath, []byte(verifiedActorApprovalYAML(false)), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	id := waitLineageApproval(t, approvalDir)
	if err := os.WriteFile(filepath.Join(approvalDir, id+".ok"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-done:
		if action != "forward" {
			t.Fatalf("want forward, got %s", action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not finish")
	}
	time.Sleep(50 * time.Millisecond)
	jsonl, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(jsonl, []byte(verifiedActorRawMarker)) {
		t.Fatal("raw marker leaked into JSONL")
	}
	siem, _ := os.ReadFile(siemPath)
	if bytes.Contains(siem, []byte(verifiedActorRawMarker)) {
		t.Fatal("raw marker leaked into SIEM")
	}
	if bytes.Contains(webhookBuf.Bytes(), []byte(verifiedActorRawMarker)) {
		t.Fatal("raw marker leaked into webhook")
	}
	ev := findAuditEvent(t, auditPath, audit.EventToolAllowed, "write_file")
	if ev.PrincipalID == "" || ev.ActingAgent == "" || ev.TransactionID == "" {
		t.Fatalf("terminal event must keep verified actor fields, got %+v", ev)
	}
	if !strings.Contains(ev.PrincipalID, "[REDACTED]") || !strings.Contains(ev.TransactionID, "[REDACTED]") {
		t.Fatalf("JSONL verified actor fields must keep [REDACTED] evidence, principal=%q txn=%q", ev.PrincipalID, ev.TransactionID)
	}
}
