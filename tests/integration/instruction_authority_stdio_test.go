package main_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/instructionauthority"
)

func TestInstructionAuthorityContinuityStdioProxy(t *testing.T) {
	mock := buildMockServer(t)
	visor := buildVisor(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	pol, err := os.CreateTemp(dir, "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(pol, `version: "1.0"
default_action: deny
settings:
  instruction_authority_continuity: true
servers:
  - name: "%s"
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
`, mock); err != nil {
		t.Fatal(err)
	}
	pol.Close()

	cmd := exec.Command(visor, "serve", "-server", mock, "-policy", pol.Name(), "-audit-log", auditPath)
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

	assertRPCError(2, map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/test"}}, "instruction authority envelope missing")

	obj := instructionauthority.NewOriginObject("SENTINEL_H32_CONTENT", instructionauthority.Origin{Principal: "SENTINEL_H32_ORIGIN", TrustClass: instructionauthority.TrustUntrustedMCPResponse}, instructionauthority.ReprMCPOutput, "SENTINEL_H32_EFFECT", true)
	obj = instructionauthority.ApplyTransform(obj, instructionauthority.Transform{Transformer: "agent_summarizer", To: instructionauthority.ReprAgentSummary, NewContent: "summary"}, nil, nil)
	obj = instructionauthority.ApplyTransform(obj, instructionauthority.Transform{Transformer: "memory_goal_persistor", To: instructionauthority.ReprPersistentGoal, Via: instructionauthority.ReprSessionMemory, NewContent: "goal"}, nil, nil)
	obj = instructionauthority.ApplyTransform(obj, instructionauthority.Transform{Transformer: "goal_handoff", To: instructionauthority.ReprSecondAgentMessage, VisibleRole: instructionauthority.RoleUser, NewContent: "SENTINEL_H32_CONTENT"}, nil, nil)
	root := instructionauthority.EvaluationRoot{Origin: obj.Provenance.Origin, InstructionBearing: true, EffectClass: obj.EffectClass, ContentSHA256: obj.History[0].ParentDigest}
	assertRPCError(3, map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/test"}, "_meta": map[string]any{"mcp-visor/instruction-authority/v1": map[string]any{"instruction_object": obj, "evaluation_root": map[string]any{"origin": root.Origin, "instruction_bearing": root.InstructionBearing, "effect_class": root.EffectClass, "content_sha256": root.ContentSHA256}}}}, "insufficient authority")

	honest := instructionauthority.NewOriginObject("read README", instructionauthority.Origin{Principal: "user:alice", TrustClass: instructionauthority.TrustTrustedUser}, instructionauthority.ReprMCPOutput, "FILE_READ", true)
	hroot := instructionauthority.EvaluationRoot{Origin: honest.Provenance.Origin, InstructionBearing: true, EffectClass: honest.EffectClass, ContentSHA256: honest.Provenance.ContentSHA256}
	if err := sendMessage(w, map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "file_read", "arguments": map[string]any{"path": "/tmp/test"}, "_meta": map[string]any{"mcp-visor/instruction-authority/v1": map[string]any{"instruction_object": honest, "evaluation_root": map[string]any{"origin": hroot.Origin, "instruction_bearing": hroot.InstructionBearing, "effect_class": hroot.EffectClass, "content_sha256": hroot.ContentSHA256}}}}}); err != nil {
		t.Fatal(err)
	}
	ok, err := readMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	if ok["error"] != nil || ok["result"] == nil {
		t.Fatalf("authorized call: %#v", ok)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	denies, allows := strings.Count(s, `"event_type":"tool_call_denied"`), strings.Count(s, `"event_type":"tool_call_allowed"`)
	if denies != 2 || allows != 1 {
		t.Fatalf("denies=%d allows=%d audit=%s", denies, allows, s)
	}
	for _, sent := range []string{"SENTINEL_H32_CONTENT", "SENTINEL_H32_ORIGIN", "SENTINEL_H32_EFFECT"} {
		if strings.Contains(s, sent) {
			t.Fatalf("audit leaked %s", sent)
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
