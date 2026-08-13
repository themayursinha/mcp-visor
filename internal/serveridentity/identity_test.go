package serveridentity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecutable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "demo-bin")
	content := []byte("#!/bin/sh\nprintf 'demo server'\n")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerIdentityResolveStdioExecutableHashesResolvedCommand(t *testing.T) {
	bin := writeExecutable(t)
	r, err := ResolveStdioExecutable(bin)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Kind != KindStdioInvocationSHA256V1 {
		t.Fatalf("expected kind %s, got %q", KindStdioInvocationSHA256V1, r.Kind)
	}
	if !strings.HasPrefix(r.Digest, "sha256:") || len(r.Digest) != len("sha256:")+64 {
		t.Fatalf("expected sha256:<64 lowercase hex> digest, got %q", r.Digest)
	}
	if r.Digest != strings.ToLower(r.Digest) {
		t.Fatalf("expected lowercase hex digest, got %q", r.Digest)
	}
}

func TestServerIdentityResolveStdioExecutableRejectsMissingCommand(t *testing.T) {
	if _, err := ResolveStdioExecutable(""); err == nil {
		t.Fatal("empty command must be rejected")
	}
	if _, err := ResolveStdioExecutable(filepath.Join(t.TempDir(), "definitely-not-a-real-binary-xyz")); err == nil {
		t.Fatal("missing command must be rejected")
	}
}

func TestServerIdentityResolveStdioExecutableRejectsDirectoryOrNonRegularFile(t *testing.T) {
	if _, err := ResolveStdioExecutable(t.TempDir()); err == nil {
		t.Fatal("directory must be rejected")
	}
	path := filepath.Join(t.TempDir(), "non-exec")
	if err := os.WriteFile(path, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveStdioExecutable(path); err == nil {
		t.Fatal("non-executable file must be rejected")
	}
}
