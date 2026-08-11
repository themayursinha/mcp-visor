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

// ResolveStdioInvocation binds the full invocation into the identity: the
// resolved launcher executable artifact, each argument verbatim (the
// selection, e.g. the npx/uvx package spec), and — when an argument resolves
// to a local regular file — that payload file's content. Two servers launched
// through the same runner with different payloads therefore get different
// digests, closing the P1 confused-deputy gap for shared launchers.
func ResolveStdioInvocation(command string, args []string) (Resolved, error) {
	if command == "" {
		return Resolved{}, fmt.Errorf("resolve stdio invocation: command is empty")
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio invocation %q: %w", command, err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio invocation symlinks %q: %w", path, err)
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio invocation stat %q: %w", resolvedPath, err)
	}
	if !info.Mode().IsRegular() {
		return Resolved{}, fmt.Errorf("resolve stdio invocation %q: not a regular file", resolvedPath)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return Resolved{}, fmt.Errorf("resolve stdio invocation %q: not executable", resolvedPath)
	}

	f, err := os.Open(resolvedPath)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio invocation open %q: %w", resolvedPath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio invocation hash %q: %w", resolvedPath, err)
	}
	for _, arg := range args {
		h.Write([]byte{0x00})
		h.Write([]byte(arg))
		// When the argument selects a local payload file (for example a
		// server script), bind that file's content so a content change
		// changes the identity. Non-file args (npx/uvx package specs) are
		// bound by their literal value above.
		if p, err := filepath.EvalSymlinks(arg); err == nil {
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				h.Write([]byte{0x00})
				af, err := os.Open(p)
				if err != nil {
					return Resolved{}, fmt.Errorf("resolve stdio invocation payload %q: %w", arg, err)
				}
				if _, err := io.Copy(h, af); err != nil {
					af.Close()
					return Resolved{}, fmt.Errorf("resolve stdio invocation payload hash %q: %w", arg, err)
				}
				af.Close()
			}
		}
	}
	return Resolved{
		Kind:   KindStdioExecutableSHA256,
		Digest: "sha256:" + hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// ResolveStdioExecutable hashes the executable artifact selected by the
// trusted launcher command with no arguments. It is retained for callers that
// launch a direct executable without a payload selector.
func ResolveStdioExecutable(command string) (Resolved, error) {
	return ResolveStdioInvocation(command, nil)
}
