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
	"sort"
)

// KindStdioExecutableSHA256 is the only attestation kind this slice supports.
const KindStdioExecutableSHA256 = "stdio_executable_sha256"

// Resolved carries the immutable identity evidence for the launched stdio
// executable. It deliberately contains no local paths or file contents.
type Resolved struct {
	Kind   string
	Digest string
}

// ResolveStdioInvocation binds a locally resolved stdio invocation into the
// identity: the resolved launcher executable artifact and each argument
// verbatim. Only the policy-declared entry argument positions (zero-based
// indexes into args, excluding the executable) additionally bind the resolved
// local regular-file content at that position; every other argument is bound
// by its literal bytes only. Undeclared file-valued arguments — logs,
// databases, datasets, sockets, and output paths — are never opened or
// hashed, so mutable runtime data cannot change the identity. Two servers
// launched through the same runner with different declared local payloads
// therefore get different digests, closing the P1 confused-deputy gap for
// shared launchers.
//
// Dynamic registry runners select executable package bytes from a registry
// or package cache at runtime, and the literal package spec does not bind the
// artifact that will execute. ResolveStdioInvocation therefore returns an
// error for every recognized canonical form (npx, uvx, bunx, pnpx, pnx, npm
// exec, npm x, yarn dlx, pnpm dlx, bun x, uv tool run), and a configured
// attestation fails closed through the existing unresolved-identity path
// instead of claiming a content pin. Only exact canonical executable names
// and exact leading subcommand tuples are recognized; options-before-
// subcommand, renamed launchers, and shell wrappers are not inferred.
func ResolveStdioInvocation(command string, args []string, entryArgPositions []int) (Resolved, error) {
	if command == "" {
		return Resolved{}, fmt.Errorf("resolve stdio invocation: command is empty")
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio invocation %q: %w", command, err)
	}
	if launcher := unpinnableLauncher(command, path, args); launcher != "" {
		return Resolved{}, fmt.Errorf("resolve stdio invocation: launcher %q selects a registry payload that cannot be content-pinned", launcher)
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

	// Normalize declared entry positions: sort a copy into a set so YAML
	// list order is never part of identity and the caller's slice is never
	// mutated. Out-of-range positions are policy errors and fail closed.
	declared := make(map[int]struct{}, len(entryArgPositions))
	positions := append([]int(nil), entryArgPositions...)
	sort.Ints(positions)
	for _, pos := range positions {
		if pos < 0 || pos >= len(args) {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry position %d: out of range for %d args", pos, len(args))
		}
		declared[pos] = struct{}{}
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
	for i, arg := range args {
		h.Write([]byte{0x00})
		h.Write([]byte(arg))
		// Only a policy-declared entry payload position is content-bound.
		// Undeclared file-valued args are bound by their literal bytes
		// above and are never opened or hashed; dynamic registry launcher
		// package specs never reach this point because the launcher itself
		// is rejected as unpinnable.
		if _, ok := declared[i]; !ok {
			continue
		}
		p, err := filepath.EvalSymlinks(arg)
		if err != nil {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload %q: %w", arg, err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload %q: %w", arg, err)
		}
		if !fi.Mode().IsRegular() {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload %q: not a regular file", arg)
		}
		h.Write([]byte{0x00})
		af, err := os.Open(p)
		if err != nil {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload %q: %w", arg, err)
		}
		if _, err := io.Copy(h, af); err != nil {
			af.Close()
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload hash %q: %w", arg, err)
		}
		af.Close()
	}
	return Resolved{
		Kind:   KindStdioExecutableSHA256,
		Digest: "sha256:" + hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// unpinnableLauncher returns the recognized canonical dynamic registry-runner
// invocation label for the command, or "" when the command selects a
// direct/local artifact. Both the operator-supplied command basename and the
// pre-symlink exec.LookPath basename are checked so bare commands and
// absolute/symlink paths are classified identically.
//
// Recognized unconditional executable basenames: npx, uvx, bunx, pnpx, pnx.
// Recognized exact leading subcommand tuples: npm exec, npm x, yarn dlx,
// pnpm dlx, bun x, uv tool run. Only these canonical names and their exact
// leading argv positions are classified; options before the subcommand,
// renamed launchers, Corepack/shell wrappers, and later argv words (for
// example x in `npm run x`) are never inferred. Other package-manager
// subcommands (run, install, ci, add, exec local, tool install) remain
// direct/local artifacts.
func unpinnableLauncher(command, lookPath string, args []string) string {
	for _, c := range []string{filepath.Base(command), filepath.Base(lookPath)} {
		switch c {
		case "npx", "uvx", "bunx", "pnpx", "pnx":
			return c
		case "npm":
			if len(args) > 0 && args[0] == "exec" {
				return "npm exec"
			}
			if len(args) > 0 && args[0] == "x" {
				return "npm x"
			}
		case "yarn":
			if len(args) > 0 && args[0] == "dlx" {
				return "yarn dlx"
			}
		case "pnpm":
			if len(args) > 0 && args[0] == "dlx" {
				return "pnpm dlx"
			}
		case "bun":
			if len(args) > 0 && args[0] == "x" {
				return "bun x"
			}
		case "uv":
			if len(args) >= 2 && args[0] == "tool" && args[1] == "run" {
				return "uv tool run"
			}
		}
	}
	return ""
}

// ResolveStdioExecutable hashes the executable artifact selected by the
// trusted launcher command with no arguments. It is retained for callers that
// launch a direct executable without a payload selector.
func ResolveStdioExecutable(command string) (Resolved, error) {
	return ResolveStdioInvocation(command, nil, nil)
}
