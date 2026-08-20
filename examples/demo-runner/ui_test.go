package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUIRejectsNonLoopback(t *testing.T) {
	if err := runUI("0.0.0.0:9092"); err == nil {
		t.Fatal("runUI must fail closed on wildcard bind")
	}
}

func TestProofHTMLIsProofInterface(t *testing.T) {
	t.Parallel()
	html := string(proofHTML)
	for _, bad := range []string{"Control Plane", "SOC dashboard", "enterprise console", "AI gateway"} {
		if strings.Contains(html, bad) {
			t.Errorf("proof HTML must not use product-dashboard language %q", bad)
		}
	}
	if !strings.Contains(html, "No deny recorded.") {
		t.Fatal("empty policy panel must not assume a deny")
	}
	if !strings.Contains(html, "Non-relay is not proven") {
		t.Fatal("empty observations must not claim non-relay")
	}
	if !strings.Contains(html, "/api/snapshot") {
		t.Fatal("HTML must fetch the live snapshot, not a hardcoded story")
	}
}

func TestSnapshotReadsDenyFromLedger(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	obs := filepath.Join(dir, "obs.jsonl")
	line := `{"event_type":"tool_call_denied","policy_decision":"deny","policy_rule":"block_sensitive_egress","tool":"http_post"}` + "\n"
	if err := os.WriteFile(audit, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := readSnapshot(audit, obs)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshotHasDeny(s) {
		t.Fatal("deny present in the ledger must appear in the snapshot")
	}
}

func TestHandleSnapshotMalformedLedgerHasNoDecision(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	obs := filepath.Join(dir, "obs.jsonl")
	if err := os.WriteFile(audit, []byte("{\"event_type\":\"tool_call_denied\"}\n{truncated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obs, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &proofServer{auditLog: audit, observeLog: obs}
	ps.sequenceDone.Store(true)
	rec := httptest.NewRecorder()
	ps.handleSnapshot(rec, httptest.NewRequest(http.MethodGet, "/api/snapshot", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("malformed ledger must yield no snapshot decision, got %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"integrity":"ok"`) {
		t.Fatal("malformed ledger must not report integrity ok")
	}
}
