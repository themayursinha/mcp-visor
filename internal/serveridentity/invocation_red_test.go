package serveridentity

import (
	"os"
	"path/filepath"
	"strings"
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

// P1 RED: dynamic registry launchers (npx, uvx) select a package from a
// registry at runtime; the literal package spec does not bind the artifact
// that will actually execute, so attestation must fail closed instead of
// returning a digest for the literal spec. On the vulnerable implementation
// this test fails because the resolver hashes the literal spec and returns a
// digest.
func TestServerIdentityUnpinnableRegistryLauncherRejected(t *testing.T) {
	tests := []struct {
		name     string
		launcher string
		spec     string
	}{
		{"npx package spec", "npx", "@example/mcp-server@1.0.0"},
		{"uvx package spec", "uvx", "example-server==1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launcher := writePayload(t, tt.launcher, "#!/bin/sh\nprintf 'registry launcher'\n")
			_, err := ResolveStdioInvocation(launcher, []string{tt.spec})
			if err == nil {
				t.Fatalf("P1: %s invocation must be rejected as unpinnable, got nil error", tt.name)
			}
			if !strings.Contains(err.Error(), tt.launcher) {
				t.Fatalf("expected error to identify launcher %q, got %v", tt.launcher, err)
			}
		})
	}
}
