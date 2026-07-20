package approval_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/approval"
	"github.com/themayursinha/mcp-visor/internal/receipt"
)

func TestDurableEnginePersistsPendingAndReloads(t *testing.T) {
	dir := t.TempDir()
	base, err := approval.NewEngine("", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// No live backend: durable path should park pending request on disk.
	de, err := approval.NewDurableEngine(base, dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := de.RequestApproval(approval.Request{
		ID:        "req-1",
		Tool:      "shell_exec",
		Server:    "shell",
		Reason:    "high risk",
		RiskLevel: "high",
		SessionID: "sess-a",
		AgentID:   "agent-a",
		Arguments: map[string]any{"cmd": "id"},
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if dec.Approved || !dec.RequiresApproval || dec.ExecutionID == "" {
		t.Fatalf("expected pending approval decision, got %+v", dec)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected pending request file on disk")
	}

	// Reopen durable engine from same dir — pending must reload.
	de2, err := approval.NewDurableEngine(base, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := de2.GetPendingRequest(dec.ExecutionID)
	if err != nil {
		t.Fatalf("reload pending: %v", err)
	}
	if pending.Tool != "shell_exec" || pending.SessionID != "sess-a" {
		t.Fatalf("unexpected pending payload: %+v", pending)
	}
}

func TestDurableEngineSessionIsolation(t *testing.T) {
	dir := t.TempDir()
	de, err := approval.NewDurableEngine(nil, dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	decB, err := de.RequestApproval(approval.Request{
		ID: "b1", Tool: "send", Server: "http", SessionID: "sess-b", AgentID: "agent",
		Reason: "needs approval", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decB.RequiresApproval {
		t.Fatal("expected pending for session B")
	}

	rec, err := receipt.NewReceipt(
		"foreign-exec", "sess-a", "agent",
		"http", "send",
		"reason", "{}",
		"1.0", "policy", "chain",
		"ok", "high", "tester",
		"approve", time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := de.SubmitReceipt(raw); err == nil {
		t.Fatal("expected unknown execution ID for foreign receipt")
	}

	if _, err := de.GetPendingRequest(decB.ExecutionID); err != nil {
		t.Fatalf("session B pending lost: %v", err)
	}
}

func TestDurableEngineReceiptCacheIsolatesAgents(t *testing.T) {
	pair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	de, err := approval.NewDurableEngine(nil, dir, pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pendingA, err := de.RequestApproval(approval.Request{
		ID: "agent-a", Tool: "send", Server: "http", SessionID: "shared-session", AgentID: "agent-a",
		Reason: "needs approval", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	approvedA, err := receipt.NewReceipt(
		pendingA.ExecutionID, "shared-session", "agent-a", "http", "send",
		"reason", "{}", "1.0", "policy", "chain", "approved", "high", "operator", "approve", time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvedA.Sign(pair); err != nil {
		t.Fatal(err)
	}
	raw, err := approvedA.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := de.SubmitReceipt(raw); err != nil {
		t.Fatal(err)
	}

	decisionB, err := de.RequestApproval(approval.Request{
		ID: "agent-b", Tool: "send", Server: "http", SessionID: "shared-session", AgentID: "agent-b",
		Reason: "needs separate approval", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decisionB.Approved || !decisionB.RequiresApproval {
		t.Fatalf("agent B reused agent A's receipt: %+v", decisionB)
	}

	reopened, err := approval.NewDurableEngine(nil, dir, pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	decisionC, err := reopened.RequestApproval(approval.Request{
		ID: "agent-c", Tool: "send", Server: "http", SessionID: "shared-session", AgentID: "agent-c",
		Reason: "needs separate approval after restart", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decisionC.Approved || !decisionC.RequiresApproval {
		t.Fatalf("agent C reused agent A's reloaded receipt: %+v", decisionC)
	}
}

func TestDurableEngineReceiptCacheKeyHasNoDelimiterCollisions(t *testing.T) {
	pair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	de, err := approval.NewDurableEngine(nil, t.TempDir(), pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pendingA, err := de.RequestApproval(approval.Request{
		ID: "agent-a", Tool: "send", Server: "http", SessionID: "shared", AgentID: "agent:a",
		Reason: "needs approval", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	approvedA, err := receipt.NewReceipt(
		pendingA.ExecutionID, "shared", "agent:a", "http", "send",
		"reason", "{}", "1.0", "policy", "chain", "approved", "high", "operator", "approve", time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvedA.Sign(pair); err != nil {
		t.Fatal(err)
	}
	raw, err := approvedA.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := de.SubmitReceipt(raw); err != nil {
		t.Fatal(err)
	}

	decisionB, err := de.RequestApproval(approval.Request{
		ID: "agent-b", Tool: "send", Server: "http", SessionID: "shared:agent", AgentID: "a",
		Reason: "needs separate approval", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decisionB.Approved || !decisionB.RequiresApproval {
		t.Fatalf("distinct identity tuple reused a colliding receipt cache key: %+v", decisionB)
	}
}

func TestDurableEngineExpiredReceiptRejected(t *testing.T) {
	dir := t.TempDir()
	de, err := approval.NewDurableEngine(nil, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := de.RequestApproval(approval.Request{
		ID: "exp-1", Tool: "tool", Server: "srv", SessionID: "s", AgentID: "a",
		Reason: "r", RiskLevel: "low",
	})
	if err != nil {
		t.Fatal(err)
	}

	rec, err := receipt.NewReceipt(
		dec.ExecutionID, "s", "a",
		"srv", "tool",
		"r", "{}",
		"1.0", "policy", "chain",
		"r", "low", "tester",
		"approve", -time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := de.SubmitReceipt(raw)
	if err == nil {
		t.Fatal("expected expired receipt error")
	}
	if out != nil && out.Approved {
		t.Fatal("expired receipt must not approve")
	}
}

func TestDurableEngineMalformedReceiptFailsClosed(t *testing.T) {
	de, err := approval.NewDurableEngine(nil, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := de.SubmitReceipt([]byte(`{not-json`)); err == nil {
		t.Fatal("malformed receipt must fail closed")
	}
}

func TestDurableEngineRejectsUnsignedReceiptAndRetainsPendingRequest(t *testing.T) {
	pair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	de, err := approval.NewDurableEngine(nil, t.TempDir(), pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := de.RequestApproval(approval.Request{
		ID: "unsigned", Tool: "shell_exec", Server: "shell", SessionID: "sess-a", AgentID: "agent-a",
		Reason: "high risk", RiskLevel: "high", Arguments: map[string]any{"cmd": "id"},
	})
	if err != nil {
		t.Fatal(err)
	}

	forged, err := receipt.NewReceipt(
		pending.ExecutionID, "sess-a", "agent-a", "shell", "shell_exec",
		"high risk", "{}", "1.0", "policy", "chain", "high risk", "high", "operator", "approve", time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := forged.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := de.SubmitReceipt(raw); err == nil {
		t.Fatal("unsigned receipt must not approve a pending request")
	}
	if _, err := de.GetPendingRequest(pending.ExecutionID); err != nil {
		t.Fatalf("invalid receipt consumed pending request: %v", err)
	}
}

func TestDurableEngineRejectsSignedReceiptWithMismatchedRequestIdentity(t *testing.T) {
	pair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	de, err := approval.NewDurableEngine(nil, t.TempDir(), pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := de.RequestApproval(approval.Request{
		ID: "identity", Tool: "shell_exec", Server: "shell", SessionID: "sess-a", AgentID: "agent-a",
		Reason: "high risk", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}

	wrongIdentity, err := receipt.NewReceipt(
		pending.ExecutionID, "sess-b", "agent-a", "shell", "shell_exec",
		"high risk", "{}", "1.0", "policy", "chain", "high risk", "high", "operator", "approve", time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongIdentity.Sign(pair); err != nil {
		t.Fatal(err)
	}
	raw, err := wrongIdentity.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := de.SubmitReceipt(raw); err == nil {
		t.Fatal("receipt for a different session must not approve the pending request")
	}
	if _, err := de.GetPendingRequest(pending.ExecutionID); err != nil {
		t.Fatalf("mismatched receipt consumed pending request: %v", err)
	}
}

func TestDurableEngineReceiptCompletionDoesNotResurrectPendingAfterRestart(t *testing.T) {
	pair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	de, err := approval.NewDurableEngine(nil, dir, pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := de.RequestApproval(approval.Request{
		ID: "complete", Tool: "shell_exec", Server: "shell", SessionID: "sess-a", AgentID: "agent-a",
		Reason: "high risk", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}

	approved, err := receipt.NewReceipt(
		pending.ExecutionID, "sess-a", "agent-a", "shell", "shell_exec",
		"high risk", "{}", "1.0", "policy", "chain", "high risk", "high", "operator", "approve", time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := approved.Sign(pair); err != nil {
		t.Fatal(err)
	}
	raw, err := approved.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decision, err := de.SubmitReceipt(raw)
	if err != nil || !decision.Approved {
		t.Fatalf("signed matching receipt should approve: decision=%+v err=%v", decision, err)
	}

	reopened, err := approval.NewDurableEngine(nil, dir, pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetPendingRequest(pending.ExecutionID); err == nil {
		t.Fatal("completed pending request must not be restored after restart")
	}
}

func TestDurableEngineReconcilesReceiptPersistedBeforePendingRemoval(t *testing.T) {
	pair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	de, err := approval.NewDurableEngine(nil, dir, pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := de.RequestApproval(approval.Request{
		ID: "crash-window", Tool: "shell_exec", Server: "shell", SessionID: "sess-a", AgentID: "agent-a",
		Reason: "high risk", RiskLevel: "high",
	})
	if err != nil {
		t.Fatal(err)
	}

	approved, err := receipt.NewReceipt(
		pending.ExecutionID, "sess-a", "agent-a", "shell", "shell_exec",
		"high risk", "{}", "1.0", "policy", "chain", "high risk", "high", "operator", "approve", time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := approved.Sign(pair); err != nil {
		t.Fatal(err)
	}
	raw, err := approved.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "receipt-"+pending.ExecutionID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := approval.NewDurableEngine(nil, dir, pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetPendingRequest(pending.ExecutionID); err == nil {
		t.Fatal("receipt persisted before a crash must suppress the matching pending request")
	}
	if got := len(reopened.PendingRequests()); got != 0 {
		t.Fatalf("completed request remained in pending queue after recovery: %d", got)
	}
}

func TestNewDurableEngineRejectsMalformedPersistedState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pending-corrupt.json"), []byte(`{not-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := approval.NewDurableEngine(nil, dir, nil); err == nil {
		t.Fatal("malformed durable approval state must prevent startup")
	}
}

func TestNewDurableEngineSkipsExpiredPersistedReceipt(t *testing.T) {
	pair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	expired, err := receipt.NewReceipt(
		"expired-receipt", "sess", "agent", "shell", "shell_exec",
		"high risk", "{}", "1.0", "policy", "chain", "high risk", "high", "operator", "approve", -time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := expired.Sign(pair); err != nil {
		t.Fatal(err)
	}
	raw, err := expired.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "receipt-expired-receipt.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	rotatedPair, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approval.NewDurableEngine(nil, dir, rotatedPair.PublicKey); err != nil {
		t.Fatalf("expired persisted receipt must not prevent startup after key rotation: %v", err)
	}
}

func TestDurableEngineRejectsUnpersistableRequestIdentities(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  approval.Request
	}{
		{
			name: "empty tool",
			req:  approval.Request{ID: "req-1", Tool: "", Server: "shell", SessionID: "session-a", AgentID: "agent-a", Reason: "high risk", RiskLevel: "high"},
		},
		{
			name: "empty server",
			req:  approval.Request{ID: "req-1", Tool: "shell_exec", Server: "", SessionID: "session-a", AgentID: "agent-a", Reason: "high risk", RiskLevel: "high"},
		},
		{
			name: "empty session ID",
			req:  approval.Request{ID: "req-1", Tool: "shell_exec", Server: "shell", SessionID: "", AgentID: "agent-a", Reason: "high risk", RiskLevel: "high"},
		},
		{
			name: "empty agent ID",
			req:  approval.Request{ID: "req-1", Tool: "shell_exec", Server: "shell", SessionID: "session-a", AgentID: "", Reason: "high risk", RiskLevel: "high"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			de, err := approval.NewDurableEngine(nil, dir, nil)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := de.RequestApproval(tc.req); err == nil {
				t.Fatal("RequestApproval accepted an identity that cannot be reloaded safely")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("invalid request must not be persisted: %v", entries)
			}
		})
	}
}

func TestDurableEngineCleanupSkipsExpiredPendingOnLoad(t *testing.T) {
	dir := t.TempDir()
	expired := []byte(`{
  "id": "exec-old",
  "tool": "t",
  "server": "s",
  "session_id": "sess",
  "agent_id": "agent",
  "created_at": "2020-01-01T00:00:00Z",
  "expires_at": "2020-01-01T01:00:00Z",
  "request_hash": "1:s:1:t:4:sess:5:agent"
}`)
	path := filepath.Join(dir, "pending-exec-old.json")
	if err := os.WriteFile(path, expired, 0o600); err != nil {
		t.Fatal(err)
	}
	de2, err := approval.NewDurableEngine(nil, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	de2.Cleanup()
	if _, err := de2.GetPendingRequest("exec-old"); err == nil {
		t.Fatal("expired pending must not be loadable")
	}
}
