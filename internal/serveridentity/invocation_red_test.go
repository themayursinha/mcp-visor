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

// P1 RED: dynamic registry launchers (npx, uvx, and canonical npm exec)
// select a package from a registry at runtime; the literal package spec does
// not bind the artifact that will actually execute, so attestation must fail
// closed instead of returning a digest for the literal spec. On the
// vulnerable implementation this test fails because the resolver hashes the
// literal spec and returns a digest for npm exec, which it does not yet
// classify as unpinnable.
func TestServerIdentityUnpinnableRegistryLauncherRejected(t *testing.T) {
	tests := []struct {
		name     string
		launcher string
		args     []string
		wantErr  string
	}{
		{"npx package spec", "npx", []string{"@example/mcp-server@1.0.0"}, "npx"},
		{"uvx package spec", "uvx", []string{"example-server==1.0.0"}, "uvx"},
		{"npm exec package spec", "npm", []string{"exec", "--", "@example/mcp-server@1.0.0"}, "npm exec"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launcher := writePayload(t, tt.launcher, "#!/bin/sh\nprintf 'registry launcher'\n")
			_, err := ResolveStdioInvocation(launcher, tt.args)
			if err == nil {
				t.Fatalf("P1: %s invocation must be rejected as unpinnable, got nil error", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error to identify %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// Negative control: an invocation whose executable happens to be named npm
// but which is NOT the canonical registry-runner subcommand (npm run) must
// still resolve. Only npm exec is classified as unpinnable; the classifier
// must not reject arbitrary npm subcommands merely because of the basename.
func TestServerIdentityNpmRunNotRejected(t *testing.T) {
	npm := writePayload(t, "npm", "#!/bin/sh\nprintf 'npm shim'\n")
	if _, err := ResolveStdioInvocation(npm, []string{"run", "local-server"}); err != nil {
		t.Fatalf("npm run must not be rejected merely because the executable is named npm: %v", err)
	}
}

// P1 RED: the full documented canonical registry-runner class. Each form
// selects executable package bytes from a registry or package cache at
// runtime; the literal package spec does not bind the artifact that will
// execute. On the vulnerable implementation every form below not already
// classified (npx, uvx, npm exec) hashes the launcher plus the literal spec
// and returns a digest, so these subtests fail with a nil error.
func TestServerIdentityDocumentedRegistryRunnersRejected(t *testing.T) {
	tests := []struct {
		name     string
		launcher string
		args     []string
		wantErr  string
	}{
		{"npx package spec", "npx", []string{"@example/mcp-server@1.0.0"}, "npx"},
		{"uvx package spec", "uvx", []string{"example-server==1.0.0"}, "uvx"},
		{"npm exec package spec", "npm", []string{"exec", "--", "@example/mcp-server@1.0.0"}, "npm exec"},
		{"npm x package spec", "npm", []string{"x", "@example/mcp-server@1.0.0"}, "npm x"},
		{"yarn dlx package spec", "yarn", []string{"dlx", "@example/mcp-server@1.0.0"}, "yarn dlx"},
		{"pnpm dlx package spec", "pnpm", []string{"dlx", "@example/mcp-server@1.0.0"}, "pnpm dlx"},
		{"bunx package spec", "bunx", []string{"@example/mcp-server@1.0.0"}, "bunx"},
		{"bun x package spec", "bun", []string{"x", "@example/mcp-server@1.0.0"}, "bun x"},
		{"uv tool run package spec", "uv", []string{"tool", "run", "example-server==1.0.0"}, "uv tool run"},
		{"pnpx package spec", "pnpx", []string{"@example/mcp-server@1.0.0"}, "pnpx"},
		{"pnx package spec", "pnx", []string{"@example/mcp-server@1.0.0"}, "pnx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launcher := writePayload(t, tt.launcher, "#!/bin/sh\nprintf 'registry launcher'\n")
			res, err := ResolveStdioInvocation(launcher, tt.args)
			if err == nil {
				t.Fatalf("P1: %s invocation must be rejected as unpinnable, got digest %q and nil error", tt.name, res.Digest)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error to identify %q, got %v", tt.wantErr, err)
			}
			if res.Digest != "" {
				t.Fatalf("unpinnable invocation must not return a digest, got %q", res.Digest)
			}
		})
	}
}

// Negative control: ordinary package-manager subcommands that execute local
// scripts, add dependencies, install, or run projects must still resolve even
// though their executable is a canonical package manager. The classifier is
// a canonical-name and exact-leading-subcommand boundary; it must not scan
// later argv (npm run x), parse flags, or infer renamed wrappers.
func TestServerIdentityNonRegistryPackageManagerSubcommandsNotRejected(t *testing.T) {
	tests := []struct {
		name     string
		launcher string
		args     []string
	}{
		{"npm run local-server", "npm", []string{"run", "local-server"}},
		{"npm run x", "npm", []string{"run", "x"}},
		{"npm install", "npm", []string{"install"}},
		{"npm ci", "npm", []string{"ci"}},
		{"yarn add", "yarn", []string{"add", "example"}},
		{"pnpm add", "pnpm", []string{"add", "example"}},
		{"pnpm exec local-server", "pnpm", []string{"exec", "local-server"}},
		{"bun run local-server", "bun", []string{"run", "local-server"}},
		{"bun add example", "bun", []string{"add", "example"}},
		{"uv run local script", "uv", []string{"run", "local-script.py"}},
		{"uv tool install example", "uv", []string{"tool", "install", "example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launcher := writePayload(t, tt.launcher, "#!/bin/sh\nprintf 'package manager shim'\n")
			if _, err := ResolveStdioInvocation(launcher, tt.args); err != nil {
				t.Fatalf("negative control %s must resolve, got error: %v", tt.name, err)
			}
		})
	}
}
