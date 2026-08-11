// Package serveridentity resolves an out-of-band identity for the launched
// stdio server executable. MCP metadata (tool descriptions, schemas,
// instructions, and handshake serverInfo) is untrusted presentation data and
// is never used to satisfy an attestation.
package serveridentity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// KindStdioExecutableSHA256 is the only attestation kind this slice supports.
const KindStdioExecutableSHA256 = "stdio_executable_sha256"

// Resolved carries the immutable identity evidence for the launched stdio
// executable. It deliberately contains no local paths or file contents.
type Resolved struct {
	Kind   string
	Digest string
}

// ResolveStdioExecutable hashes the executable artifact selected by the
// trusted launcher command. The command is resolved via PATH, symlinks are
// followed, and the file must be a regular executable. Only the sha256
// digest and kind are returned; local paths never enter audit records.
func ResolveStdioExecutable(command string) (Resolved, error) {
	if command == "" {
		return Resolved{}, fmt.Errorf("resolve stdio executable: command is empty")
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio executable %q: %w", command, err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio executable symlinks %q: %w", path, err)
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio executable stat %q: %w", resolvedPath, err)
	}
	if !info.Mode().IsRegular() {
		return Resolved{}, fmt.Errorf("resolve stdio executable %q: not a regular file", resolvedPath)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return Resolved{}, fmt.Errorf("resolve stdio executable %q: not executable", resolvedPath)
	}

	f, err := os.Open(resolvedPath)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio executable open %q: %w", resolvedPath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio executable hash %q: %w", resolvedPath, err)
	}
	return Resolved{
		Kind:   KindStdioExecutableSHA256,
		Digest: "sha256:" + hex.EncodeToString(h.Sum(nil)),
	}, nil
}
