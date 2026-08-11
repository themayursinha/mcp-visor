package serveridentity

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRunner writes an executable that stands in for a shared launcher such
// as npx/uvx: the same binary selects different payloads purely through args.
func writeRunner(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runner-bin")
	content := []byte("#!/bin/sh\nprintf 'shared launcher'\n")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePayload(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// P1 RED: the same runner binary launched with different payload args must
// NOT produce identical identities. Codex P1: hashing only cfg.ServerCommand
// (e.g. "npx") ignores the package/script the args select, so benign and
// poisoned servers behind the same runner both get server_attested=true.
func TestResolveStdioInvocationBindsArgs(t *testing.T) {
	runner := writeRunner(t)
	benignPayload := writePayload(t, "benign-server.js", "serve benign")
	poisonedPayload := writePayload(t, "poisoned-server.js", "serve poisoned")

	benign, err := ResolveStdioInvocation(runner, []string{benignPayload})
	if err != nil {
		t.Fatalf("resolve benign: %v", err)
	}
	poisoned, err := ResolveStdioInvocation(runner, []string{poisonedPayload})
	if err != nil {
		t.Fatalf("resolve poisoned: %v", err)
	}
	if benign.Digest == poisoned.Digest {
		t.Fatalf("P1: same runner with different payload args must yield different digests; got %q for both", benign.Digest)
	}
}

// P1 RED: the same runner + same arg must be deterministic, and a payload
// content change must change the identity (payload is bound, not just names).
func TestResolveStdioInvocationBindsPayloadContent(t *testing.T) {
	runner := writeRunner(t)
	payloadPath := writePayload(t, "server.js", "v1")
	a, err := ResolveStdioInvocation(runner, []string{payloadPath})
	if err != nil {
		t.Fatalf("resolve v1: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := ResolveStdioInvocation(runner, []string{payloadPath})
	if err != nil {
		t.Fatalf("resolve v2: %v", err)
	}
	if a.Digest == b.Digest {
		t.Fatalf("P1: payload content change must change the digest; got %q for both", a.Digest)
	}
}
