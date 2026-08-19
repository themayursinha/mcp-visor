package main

import (
	"os"
	"path/filepath"
	"testing"
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
	if err := os.WriteFile(allowOnly, []byte(`{"event_type":"tool_call_allowed","policy_decision":"allow","hash":"abc","prev_hash":"","chain_index":1}`+"\n"), 0o600); err != nil {
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
