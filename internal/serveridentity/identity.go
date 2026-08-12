// Package serveridentity resolves an out-of-band identity for the launched
// stdio server executable. MCP metadata (tool descriptions, schemas,
// instructions, and handshake serverInfo) is untrusted presentation data and
// is never used to satisfy an attestation.
package serveridentity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// KindStdioInvocationSHA256V1 is the only attestation kind this slice
// supports: a versioned, deterministic, locally measured stdio invocation
// identity. The v1 suffix is intentional: the digest serialization is part
// of the security contract, and future format changes use a new version
// rather than silently reinterpreting existing pins.
const KindStdioInvocationSHA256V1 = "stdio_invocation_sha256_v1"

// Framed serialization contract (stdio_invocation_sha256_v1).
//
// The digest input is a sequence of self-delimiting framed fields:
//
//	field := tag(1 byte) | index(8-byte big-endian uint64) |
//	         length(8-byte big-endian uint64) | data(exactly length bytes)
//
// and the full input is:
//
//	format marker field   (tag=0x01, index=0, data="stdio_invocation_sha256_v1")
//	executable field      (tag=0x02, index=0, data=resolved launcher file bytes)
//	for each argument i in argv order:
//	  argument field      (tag=0x03, index=i, data=literal argument bytes)
//	  if i is declared:   entry payload field (tag=0x04, index=i,
//	                       data=resolved local regular-file bytes)
//
// The tag separates component domains, the fixed-width index fixes ordinal
// position, and the fixed-width length prefix makes every field
// self-delimiting without relying on any separator byte. Different component
// structures therefore never serialize to the same hash input (injective
// framing): the Codex collision class where executable bytes plus a
// NUL-separated argv are indistinguishable from a different executable whose
// content embeds that same byte sequence cannot occur, because the
// executable field carries its own explicit length and the argument fields
// carry their own tags, indexes, and lengths. The format marker is written
// first so a future serialization version produces a different digest even
// for an identical invocation.
const (
	tagFormat       byte = 0x01 // format/version marker field
	tagExecutable   byte = 0x02 // resolved launcher executable content
	tagArgument     byte = 0x03 // literal argv value at ordinal index
	tagEntryPayload byte = 0x04 // declared entry payload content at arg index
)

// writeFieldHeader writes tag|index|length into h without the data bytes,
// so the caller can stream data of the declared length separately (used for
// file contents whose size is known from Stat).
func writeFieldHeader(h hash.Hash, tag byte, index, length uint64) {
	var buf [8]byte
	h.Write([]byte{tag})
	binary.BigEndian.PutUint64(buf[:], index)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], length)
	h.Write(buf[:])
}

// writeField writes one complete framed field tag|index|length|data.
func writeField(h hash.Hash, tag byte, index uint64, data []byte) {
	writeFieldHeader(h, tag, index, uint64(len(data)))
	h.Write(data)
}

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
// The digest is a versioned, deterministic measurement: the serialized input
// is the canonical framed encoding documented above (format marker,
// executable field, then one argument field per argv value in order with an
// entry-payload field after each declared position), hashed with SHA-256 and
// returned as "sha256:" + 64 lowercase hex digits under kind
// stdio_invocation_sha256_v1. The framing is injective within the supported
// identity model: InvocationA != InvocationB implies
// CanonicalEncoding(A) != CanonicalEncoding(B).
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
	writeField(h, tagFormat, 0, []byte(KindStdioInvocationSHA256V1))
	// Executable field: explicit length from the same Stat that validated
	// the artifact, then stream the bytes. If the file changes size between
	// Stat and read, the field header and the data disagree, so resolution
	// fails closed instead of producing a digest for a moving target.
	writeFieldHeader(h, tagExecutable, 0, uint64(info.Size()))
	n, err := io.Copy(h, f)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve stdio invocation hash %q: %w", resolvedPath, err)
	}
	if n != info.Size() {
		return Resolved{}, fmt.Errorf("resolve stdio invocation %q: size changed while hashing (%d != %d)", resolvedPath, n, info.Size())
	}
	for i, arg := range args {
		writeField(h, tagArgument, uint64(i), []byte(arg))
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
		af, err := os.Open(p)
		if err != nil {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload %q: %w", arg, err)
		}
		// Entry payload field: tag=tagEntryPayload, index=the declared arg
		// position, length from the stat above, then the streamed bytes.
		writeFieldHeader(h, tagEntryPayload, uint64(i), uint64(fi.Size()))
		pn, err := io.Copy(h, af)
		af.Close()
		if err != nil {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload hash %q: %w", arg, err)
		}
		if pn != fi.Size() {
			return Resolved{}, fmt.Errorf("resolve stdio invocation entry payload %q: size changed while hashing (%d != %d)", arg, pn, fi.Size())
		}
	}
	return Resolved{
		Kind:   KindStdioInvocationSHA256V1,
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
