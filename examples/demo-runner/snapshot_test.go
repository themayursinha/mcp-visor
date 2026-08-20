package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/demoutil"
)

func TestRejectNonLoopbackAddr(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{
		"0.0.0.0:9092",
		":9092",
		"[::]:9092",
		"192.168.1.5:9092",
		"10.0.0.1:80",
		"172.16.0.1:9092",
		"8.8.8.8:9092",
		"100.63.255.255:9092",
		"100.128.0.1:9092",
	} {
		if err := validateListenAddr(addr); err == nil {
			t.Errorf("expected reject for wildcard/LAN/public %q", addr)
		}
	}
	for _, addr := range []string{
		"127.0.0.1:9092",
		"127.0.0.1:0",
		"localhost:9092",
		"[::1]:9092",
		"100.64.0.1:9092",
		"100.64.1.2:9092",
		"100.127.255.254:9092",
	} {
		if err := validateListenAddr(addr); err != nil {
			t.Errorf("allowed bind %q: %v", addr, err)
		}
	}
}

func TestSnapshotEmptyHasNoDeny(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	audit := filepath.Join(dir, "missing-audit.jsonl")
	obs := filepath.Join(dir, "missing-obs.jsonl")

	s, err := readSnapshot(audit, obs)
	if err != nil {
		t.Fatalf("readSnapshot missing files: %v", err)
	}
	if snapshotHasDeny(s) {
		t.Fatal("empty/missing ledger must not invent policy_decision=deny or tool_call_denied")
	}
	if len(s.AuditEvents) != 0 {
		t.Fatalf("expected no audit events, got %d", len(s.AuditEvents))
	}

	if err := os.WriteFile(filepath.Join(dir, "empty.jsonl"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = readSnapshot(filepath.Join(dir, "empty.jsonl"), filepath.Join(dir, "empty.jsonl"))
	if err != nil {
		t.Fatalf("readSnapshot empty files: %v", err)
	}
	if snapshotHasDeny(s) {
		t.Fatal("empty JSONL must not invent a deny")
	}

	allowOnly := filepath.Join(dir, "allow.jsonl")
	if err := os.WriteFile(allowOnly, []byte(`{"event_type":"tool_call_allowed","policy_decision":"allow"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = readSnapshot(allowOnly, filepath.Join(dir, "empty.jsonl"))
	if err != nil {
		t.Fatalf("readSnapshot allow-only: %v", err)
	}
	if snapshotHasDeny(s) {
		t.Fatal("allow-only ledger must not invent a deny")
	}
}

func TestSnapshotEmptyObservationsDoNotProveNonRelay(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	obs := filepath.Join(dir, "obs.jsonl")
	if err := os.WriteFile(audit, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obs, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := readSnapshot(audit, obs)
	if err != nil {
		t.Fatalf("readSnapshot: %v", err)
	}
	if nonRelayProven(s) {
		t.Fatal("empty observe-log must not prove the denied call never reached the server")
	}
	if httpPost300Received(s) {
		t.Fatal("empty observe-log must not claim http_post #300 was received")
	}
}

func TestIncompleteObservationsDoNotProveNonRelay(t *testing.T) {
	t.Parallel()
	s := Snapshot{
		Observations: []demoutil.ObsLine{
			{Tool: "file_read", RequestID: 100, Received: true},
		},
		AuditEvents: []map[string]any{
			{"event_type": "tool_call_denied", "tool": "http_post", "policy_decision": "deny"},
		},
	}
	if nonRelayProven(s) {
		t.Fatal("incomplete observe-log must not prove the denied call never reached the server")
	}
	if httpPost300Received(s) {
		t.Fatal("incomplete observe-log must not claim http_post #300 was received")
	}
}

func TestProofIntegrityRejectsPartialLedger(t *testing.T) {
	t.Parallel()
	obs := []demoutil.ObsLine{
		{Tool: "file_read", RequestID: 100, Received: true},
		{Tool: "file_read", RequestID: 200, Received: true},
	}
	partial := Snapshot{
		Observations: obs,
		AuditEvents: []map[string]any{
			{
				"event_type":      "tool_call_denied",
				"tool":            "http_post",
				"policy_decision": "deny",
				"policy_rule":     "unrelated",
			},
			{
				"event_type":     "session_tainted",
				"tool":           "file_read",
				"session_taints": []any{"other_taint"},
			},
		},
	}
	if proofIntegrity(partial) == "ok" {
		t.Fatal("unrelated/partial ledger must not report integrity ok")
	}

	brokenChain := hashedCanonicalProofSnapshot(t)
	brokenChain.AuditEvents[1]["prev_hash"] = "not-the-previous-hash"
	if proofIntegrity(brokenChain) == "ok" {
		t.Fatal("broken hash chain must not report integrity ok")
	}

	missingAllows := hashedCanonicalProofSnapshot(t)
	missingAllows.AuditEvents = missingAllows.AuditEvents[2:]
	if proofIntegrity(missingAllows) == "ok" {
		t.Fatal("ledger without file_read allows must not report integrity ok")
	}

	unhashedDeny := hashedCanonicalProofSnapshot(t)
	delete(unhashedDeny.AuditEvents[3], "hash")
	if proofIntegrity(unhashedDeny) == "ok" {
		t.Fatal("deny without hash must not report integrity ok")
	}

	unhashedTaint := hashedCanonicalProofSnapshot(t)
	unhashedTaint.AuditEvents[2]["hash"] = ""
	if proofIntegrity(unhashedTaint) == "ok" {
		t.Fatal("taint without hash must not report integrity ok")
	}
}

func TestReadSnapshotRejectsMalformedLedger(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	obs := filepath.Join(dir, "obs.jsonl")
	body := `{"event_type":"tool_call_allowed","tool":"file_read","hash":"h1"}` + "\n" + `{not-json` + "\n"
	if err := os.WriteFile(audit, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obs, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshot(audit, obs); err == nil {
		t.Fatal("malformed audit JSONL must fail closed, not skip the bad line")
	}

	if err := os.WriteFile(audit, []byte(`{"event_type":"tool_call_allowed","tool":"file_read","hash":"h1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obs, []byte("{truncated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshot(audit, obs); err == nil {
		t.Fatal("malformed observe-log must fail closed, not skip the bad line")
	}
}

func TestReadSnapshotRejectsUnverifiableHash(t *testing.T) {
	t.Parallel()
	snap := hashedCanonicalProofSnapshot(t)
	snap.AuditEvents[3]["tool"] = "slack_send_message"
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	obsPath := filepath.Join(dir, "obs.jsonl")
	var body []byte
	for _, ev := range snap.AuditEvents {
		line, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, line...)
		body = append(body, '\n')
	}
	if err := os.WriteFile(auditPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obsPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshot(auditPath, obsPath); err == nil {
		t.Fatal("payload mutation with stored hash must fail closed at snapshot read")
	}
}

func TestProofIntegrityAcceptsCanonicalSequence(t *testing.T) {
	t.Parallel()
	if got := proofIntegrity(hashedCanonicalProofSnapshot(t)); got != "ok" {
		t.Fatalf("canonical proof: %s", got)
	}
}

func TestProofIntegrityRejectsPayloadMutationWithUnchangedHash(t *testing.T) {
	t.Parallel()
	base := hashedCanonicalProofSnapshot(t)
	if got := proofIntegrity(base); got != "ok" {
		t.Fatalf("hashed canonical proof must pass before mutation: %s", got)
	}

	mutatedTimestamp := cloneProofSnapshot(base)
	mutatedTimestamp.AuditEvents[3]["timestamp"] = "2099-01-01T00:00:00Z"
	if proofIntegrity(mutatedTimestamp) == "ok" {
		t.Fatal("payload mutation with unchanged hash/prev_hash/chain_index must not report integrity ok")
	}

	mutatedTool := cloneProofSnapshot(base)
	mutatedTool.AuditEvents[0]["tool"] = "file_write"
	if proofIntegrity(mutatedTool) == "ok" {
		t.Fatal("mutated tool with unchanged hash must not report integrity ok")
	}

	mutatedRule := cloneProofSnapshot(base)
	mutatedRule.AuditEvents[3]["policy_rule"] = "unrelated_rule"
	if proofIntegrity(mutatedRule) == "ok" {
		t.Fatal("mutated policy_rule with unchanged hash must not report integrity ok")
	}

	mutatedDecision := cloneProofSnapshot(base)
	mutatedDecision.AuditEvents[3]["policy_decision"] = "allow"
	if proofIntegrity(mutatedDecision) == "ok" {
		t.Fatal("mutated policy_decision with unchanged hash must not report integrity ok")
	}

	mutatedTaint := cloneProofSnapshot(base)
	mutatedTaint.AuditEvents[2]["session_taints"] = []any{"other_taint"}
	if proofIntegrity(mutatedTaint) == "ok" {
		t.Fatal("mutated taint with unchanged hash must not report integrity ok")
	}

	mutatedHash := cloneProofSnapshot(base)
	mutatedHash.AuditEvents[3]["hash"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if proofIntegrity(mutatedHash) == "ok" {
		t.Fatal("arbitrarily modified hash must not report integrity ok")
	}
}

func hashedCanonicalProofSnapshot(t *testing.T) Snapshot {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	events := []audit.Event{
		{EventType: audit.EventToolAllowed, SessionID: "proof", Server: "mock", Tool: "file_read", Decision: "allow"},
		{EventType: audit.EventToolAllowed, SessionID: "proof", Server: "mock", Tool: "file_read", Decision: "allow"},
		{EventType: audit.EventSessionTainted, SessionID: "proof", Server: "mock", Tool: "file_read", SessionTaints: []string{"sensitive_file_accessed"}},
		{EventType: audit.EventToolDenied, SessionID: "proof", Server: "mock", Tool: "http_post", Decision: "deny", PolicyRule: "block_sensitive_egress"},
	}
	for _, ev := range events {
		if err := l.Log(ev); err != nil {
			t.Fatalf("log audit event: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}
	parsed, err := readAuditEvents(path)
	if err != nil {
		t.Fatalf("read hashed audit events: %v", err)
	}
	if len(parsed) != 4 {
		t.Fatalf("expected 4 hashed audit events, got %d", len(parsed))
	}
	return Snapshot{
		Observations: []demoutil.ObsLine{
			{Tool: "file_read", RequestID: 100, Received: true},
			{Tool: "file_read", RequestID: 200, Received: true},
		},
		AuditEvents: parsed,
	}
}

func cloneProofSnapshot(s Snapshot) Snapshot {
	events := make([]map[string]any, len(s.AuditEvents))
	for i, ev := range s.AuditEvents {
		cp := make(map[string]any, len(ev))
		for k, v := range ev {
			cp[k] = v
		}
		events[i] = cp
	}
	obs := make([]demoutil.ObsLine, len(s.Observations))
	copy(obs, s.Observations)
	return Snapshot{Observations: obs, AuditEvents: events}
}
