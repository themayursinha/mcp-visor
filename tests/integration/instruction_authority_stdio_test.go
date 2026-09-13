package main_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/instructionauthority"
	"github.com/themayursinha/mcp-visor/internal/mcp"
)

func TestInstructionAuthorityContinuityStdioProxy(t *testing.T) {
	mock := buildMockServer(t)
	visor := buildVisor(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	capture := filepath.Join(dir, "server-in.jsonl")
	wrap := filepath.Join(dir, "wrap.sh")
	if err := os.WriteFile(wrap, []byte("#!/bin/sh\ntee -a "+capture+" | exec "+mock+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "issuer-stdio"
	enc := base64.RawURLEncoding.EncodeToString(pub)
	sid, cid := "sess-h32-stdio", "agent-h32-stdio"
	pol, err := os.CreateTemp(dir, "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(pol, `version: "1.0"
default_action: deny
settings:
  instruction_authority_continuity: true
  instruction_authority_ed25519_public_keys:
    %s: %s
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`, keyID, enc, wrap); err != nil {
		t.Fatal(err)
	}
	pol.Close()

	cmd := exec.Command(visor, "serve", "-server", wrap, "-policy", pol.Name(), "-audit-log", auditPath, "-session-id", sid, "-client-id", cid)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	w, r := bufio.NewWriter(stdin), bufio.NewReader(stdout)

	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "h32", "version": "1.0"}}})
	if _, err := readMessage(r); err != nil {
		t.Fatal(err)
	}
	_ = sendMessage(w, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	assertRPCError := func(id int, params map[string]any, want string) {
		t.Helper()
		if err := sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}); err != nil {
			t.Fatal(err)
		}
		resp, err := readMessage(r)
		if err != nil {
			t.Fatal(err)
		}
		errObj, _ := resp["error"].(map[string]any)
		if errObj == nil || errObj["code"] != float64(-32000) || errObj["message"] != want {
			t.Fatalf("id %d: %#v", id, resp)
		}
	}

	honest := instructionauthority.NewOriginObject("read README", instructionauthority.Origin{Principal: "user:alice", TrustClass: instructionauthority.TrustTrustedUser}, instructionauthority.ReprMCPOutput, "FILE_READ", true)
	hroot := instructionauthority.EvaluationRoot{Origin: honest.Provenance.Origin, InstructionBearing: true, EffectClass: honest.EffectClass, ContentSHA256: honest.Provenance.ContentSHA256}
	unsigned := map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/test"}, "_meta": map[string]any{"mcp-visor/instruction-authority/v1": map[string]any{"instruction_object": honest, "evaluation_root": map[string]any{"origin": hroot.Origin, "instruction_bearing": hroot.InstructionBearing, "effect_class": hroot.EffectClass, "content_sha256": hroot.ContentSHA256}}, "unrelated-meta-sentinel": "keep-me"}}
	assertRPCError(2, unsigned, "instruction authority assertion missing")

	obj := instructionauthority.NewOriginObject("SENTINEL_H32_CONTENT", instructionauthority.Origin{Principal: "SENTINEL_H32_ORIGIN", TrustClass: instructionauthority.TrustUntrustedMCPResponse}, instructionauthority.ReprMCPOutput, "SENTINEL_H32_EFFECT", true)
	obj = instructionauthority.ApplyTransform(obj, instructionauthority.Transform{Transformer: "agent_summarizer", To: instructionauthority.ReprAgentSummary, NewContent: "summary"}, nil, nil)
	obj = instructionauthority.ApplyTransform(obj, instructionauthority.Transform{Transformer: "memory_goal_persistor", To: instructionauthority.ReprPersistentGoal, Via: instructionauthority.ReprSessionMemory, NewContent: "goal"}, nil, nil)
	obj = instructionauthority.ApplyTransform(obj, instructionauthority.Transform{Transformer: "goal_handoff", To: instructionauthority.ReprSecondAgentMessage, VisibleRole: instructionauthority.RoleUser, NewContent: "SENTINEL_H32_CONTENT"}, nil, nil)
	root := instructionauthority.EvaluationRoot{Origin: obj.Provenance.Origin, InstructionBearing: true, EffectClass: obj.EffectClass, ContentSHA256: obj.History[0].ParentDigest}
	denyParams := stdioSign(t, priv, keyID, sid, cid, wrap, "file_read", 3, obj, root, map[string]any{"path": "/tmp/test"}, false)
	assertRPCError(3, denyParams, "insufficient authority")
	if err := sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": denyParams}); err != nil {
		t.Fatal(err)
	}
	replay, err := readMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	errObj, _ := replay["error"].(map[string]any)
	if errObj == nil || errObj["message"] != "instruction authority assertion replayed" {
		t.Fatalf("replay %#v", replay)
	}

	allowParams := stdioSign(t, priv, keyID, sid, cid, wrap, "file_read", 5, honest, hroot, map[string]any{"path": "/tmp/test"}, false)
	if err := sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": allowParams}); err != nil {
		t.Fatal(err)
	}
	ok, err := readMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	if ok["error"] != nil || ok["result"] == nil {
		t.Fatalf("authorized call: %#v", ok)
	}

	redactParams := stdioSign(t, priv, keyID, sid, cid, wrap, "file_read", 6, honest, hroot, map[string]any{"path": "/tmp/test", "token": "AKIAIOSFODNN7EXAMPLE"}, false)
	if err := sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": redactParams}); err != nil {
		t.Fatal(err)
	}
	ok2, err := readMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	if ok2["error"] != nil || ok2["result"] == nil {
		t.Fatalf("redacted call: %#v", ok2)
	}

	cap, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	cs := string(cap)
	if strings.Contains(cs, "mcp-visor/instruction-authority/v1") {
		t.Fatalf("server saw visor key: %s", cs)
	}
	if !strings.Contains(cs, "unrelated-meta-sentinel") {
		t.Fatalf("unrelated meta missing: %s", cs)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	denies, allows := strings.Count(s, `"event_type":"tool_call_denied"`), strings.Count(s, `"event_type":"tool_call_allowed"`)
	if denies != 3 || allows != 2 {
		t.Fatalf("denies=%d allows=%d audit=%s", denies, allows, s)
	}
	for _, sent := range []string{"SENTINEL_H32_CONTENT", "SENTINEL_H32_ORIGIN", "SENTINEL_H32_EFFECT", enc[:12]} {
		if strings.Contains(s, sent) {
			t.Fatalf("audit leaked %s", sent)
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

type stdioAssertion struct {
	SchemaVersion  int    `json:"schema_version"`
	KeyID          string `json:"key_id"`
	SessionID      string `json:"session_id"`
	ClientID       string `json:"client_id"`
	LogicalServer  string `json:"logical_server"`
	ToolName       string `json:"tool_name"`
	RequestSHA256  string `json:"request_sha256"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
	Nonce          string `json:"nonce"`
	IssuedAtUnix   int64  `json:"issued_at_unix"`
	ExpiresAtUnix  int64  `json:"expires_at_unix"`
	Signature      string `json:"signature"`
}

func stdioSign(t *testing.T, priv ed25519.PrivateKey, keyID, sid, cid, server, tool string, id int, obj instructionauthority.InstructionObject, root instructionauthority.EvaluationRoot, args map[string]any, _ bool) map[string]any {
	t.Helper()
	type rootWire struct {
		Origin             instructionauthority.Origin `json:"origin"`
		InstructionBearing bool                        `json:"instruction_bearing"`
		EffectClass        string                      `json:"effect_class"`
		ContentSHA256      string                      `json:"content_sha256"`
	}
	type unsignedEnv struct {
		InstructionObject instructionauthority.InstructionObject `json:"instruction_object"`
		EvaluationRoot    rootWire                               `json:"evaluation_root"`
	}
	unsigned, err := json.Marshal(unsignedEnv{InstructionObject: obj, EvaluationRoot: rootWire{Origin: root.Origin, InstructionBearing: root.InstructionBearing, EffectClass: root.EffectClass, ContentSHA256: root.ContentSHA256}})
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(unsigned, &env); err != nil {
		t.Fatal(err)
	}
	es := sha256.Sum256(unsigned)
	envHash := "sha256:" + hex.EncodeToString(es[:])
	params := map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{"mcp-visor/instruction-authority/v1": env, "unrelated-meta-sentinel": "keep-me"}}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	canon, err := mcp.CanonicalizeJSONLine(raw)
	if err != nil {
		t.Fatal(err)
	}
	stripped, err := stdioStrip(canon)
	if err != nil {
		t.Fatal(err)
	}
	rs := sha256.Sum256(bytes.TrimSuffix(stripped, []byte{'\n'}))
	reqHash := "sha256:" + hex.EncodeToString(rs[:])
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Unix()
	a := stdioAssertion{
		SchemaVersion: 1, KeyID: keyID, SessionID: sid, ClientID: cid, LogicalServer: server, ToolName: tool,
		RequestSHA256: reqHash, EnvelopeSHA256: envHash, Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		IssuedAtUnix: now, ExpiresAtUnix: now + 30,
	}
	claims, _ := json.Marshal(struct {
		SchemaVersion  int    `json:"schema_version"`
		KeyID          string `json:"key_id"`
		SessionID      string `json:"session_id"`
		ClientID       string `json:"client_id"`
		LogicalServer  string `json:"logical_server"`
		ToolName       string `json:"tool_name"`
		RequestSHA256  string `json:"request_sha256"`
		EnvelopeSHA256 string `json:"envelope_sha256"`
		Nonce          string `json:"nonce"`
		IssuedAtUnix   int64  `json:"issued_at_unix"`
		ExpiresAtUnix  int64  `json:"expires_at_unix"`
	}{a.SchemaVersion, a.KeyID, a.SessionID, a.ClientID, a.LogicalServer, a.ToolName, a.RequestSHA256, a.EnvelopeSHA256, a.Nonce, a.IssuedAtUnix, a.ExpiresAtUnix})
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, claims))
	env["assertion"] = a
	params["_meta"] = map[string]any{"mcp-visor/instruction-authority/v1": env, "unrelated-meta-sentinel": "keep-me"}
	return params
}

func stdioStrip(raw json.RawMessage) (json.RawMessage, error) {
	nl := bytes.HasSuffix(raw, []byte{'\n'})
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(req["params"], &params); err != nil {
		return nil, err
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(params["_meta"], &meta); err != nil {
		return nil, err
	}
	delete(meta, "mcp-visor/instruction-authority/v1")
	params["_meta"], _ = json.Marshal(meta)
	req["params"], _ = json.Marshal(params)
	out, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if nl {
		out = append(out, '\n')
	}
	return out, nil
}
