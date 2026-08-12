package serveridentity

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

// legacyDelimiterDigest reproduces the pre-round-7 NUL-delimited framing:
// SHA-256 over launcher artifact bytes followed by each 0x00-separated
// literal arg. It is a controlled fixture that demonstrates the old
// serialization was NOT injective: different component structures could
// serialize to the identical hash input. It is used only to prove the
// collision class exists; the resolver under test must never produce those
// ambiguous digests.
func legacyDelimiterDigest(t *testing.T, launcher string, args []string) string {
	t.Helper()
	h := sha256.New()
	f, err := os.Open(launcher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	for _, arg := range args {
		h.Write([]byte{0x00})
		h.Write([]byte(arg))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// A. Codex P1 collision case (round-7 RED): the old framing hashed
// executable bytes + NUL-separated argv identically to a different
// executable whose content embeds that same byte sequence. The framed
// serialization must produce different digests for the two invocations.
func TestFramingCodexExecutableArgCollision(t *testing.T) {
	execX := writePayload(t, "execX", "#!/bin/sh\n")
	// Executable whose content embeds X || NUL || "--safe".
	execEmbedded := writePayload(t, "execEmbedded", "#!/bin/sh\n\x00--safe")

	// Controlled demonstration of the OLD ambiguity: both invocations hash
	// to the same delimiter-framed input, so the old resolver could not
	// distinguish an executable+argv from a different executable embedding
	// the same bytes.
	old1 := legacyDelimiterDigest(t, execX, []string{"--safe"})
	old2 := legacyDelimiterDigest(t, execEmbedded, nil)
	if old1 != old2 {
		t.Fatalf("fixture broken: old delimiter framing must collide, got %q vs %q", old1, old2)
	}

	a, err := ResolveStdioInvocation(execX, []string{"--safe"}, nil)
	if err != nil {
		t.Fatalf("resolve case1: %v", err)
	}
	b, err := ResolveStdioInvocation(execEmbedded, nil, nil)
	if err != nil {
		t.Fatalf("resolve case2: %v", err)
	}
	if a.Digest == b.Digest {
		t.Fatalf("P1: framed serialization must distinguish executable+argv from embedded executable bytes; got %q for both", a.Digest)
	}
}

// B. Argument framing: a NUL byte inside a single argument must not be
// interchangeable with an argument boundary. The old framing hashed
// ["a","b"] and ["a\x00b"] to the same input; the framed serialization must
// not.
func TestFramingArgumentNULNotBoundary(t *testing.T) {
	exec := writeRunner(t)

	old1 := legacyDelimiterDigest(t, exec, []string{"a", "b"})
	old2 := legacyDelimiterDigest(t, exec, []string{"a\x00b"})
	if old1 != old2 {
		t.Fatalf("fixture broken: old delimiter framing must collide on NUL-in-arg, got %q vs %q", old1, old2)
	}

	two, err := ResolveStdioInvocation(exec, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("resolve [a b]: %v", err)
	}
	one, err := ResolveStdioInvocation(exec, []string{"a\x00b"}, nil)
	if err != nil {
		t.Fatalf("resolve [a\\x00b]: %v", err)
	}
	if two.Digest == one.Digest {
		t.Fatalf("P1: argument framing must distinguish [a b] from [a\\x00b]; got %q for both", two.Digest)
	}
}

// C. Argument order: ["a","b"] and ["b","a"] must produce different
// invocation identities because each argument carries its ordinal index.
func TestFramingArgumentOrder(t *testing.T) {
	exec := writeRunner(t)

	ab, err := ResolveStdioInvocation(exec, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("resolve [a b]: %v", err)
	}
	ba, err := ResolveStdioInvocation(exec, []string{"b", "a"}, nil)
	if err != nil {
		t.Fatalf("resolve [b a]: %v", err)
	}
	if ab.Digest == ba.Digest {
		t.Fatalf("P1: argument order must affect the digest; got %q for both", ab.Digest)
	}
}

// D. Domain separation: identical bytes must not be interchangeable between
// the executable-content domain and the argument domain; the component tag
// must affect the digest.
func TestFramingDomainSeparation(t *testing.T) {
	data := "shared-bytes"

	// The same byte string as executable content (no args) vs as an
	// argument value (different executable) must yield different digests.
	execAsContent := writePayload(t, "exec-as-content", data)
	execOther := writePayload(t, "exec-other", "#!/bin/sh\n")

	asExec, err := ResolveStdioInvocation(execAsContent, nil, nil)
	if err != nil {
		t.Fatalf("resolve exec-content: %v", err)
	}
	asArg, err := ResolveStdioInvocation(execOther, []string{data}, nil)
	if err != nil {
		t.Fatalf("resolve arg-content: %v", err)
	}
	if asExec.Digest == asArg.Digest {
		t.Fatalf("P1: component domain must affect the digest; got %q for both", asExec.Digest)
	}
}

// E. Entry payload position: two identical payload files referenced from
// different declared argument positions must produce different invocation
// identities because the entry-payload field carries the declared arg index.
func TestFramingEntryPayloadPosition(t *testing.T) {
	exec := writeRunner(t)
	pa := writePayload(t, "a.js", "module identical")
	pb := writePayload(t, "b.js", "module identical")

	pos0, err := ResolveStdioInvocation(exec, []string{pa, pb}, []int{0})
	if err != nil {
		t.Fatalf("resolve declared [0]: %v", err)
	}
	pos1, err := ResolveStdioInvocation(exec, []string{pa, pb}, []int{1})
	if err != nil {
		t.Fatalf("resolve declared [1]: %v", err)
	}
	if pos0.Digest == pos1.Digest {
		t.Fatalf("P1: declared entry payload position must affect the digest; got %q for both", pos0.Digest)
	}

	// Same path at different declared positions: identical args, identical
	// payload content, only the declared index differs.
	dup0, err := ResolveStdioInvocation(exec, []string{pa, pa}, []int{0})
	if err != nil {
		t.Fatalf("resolve dup declared [0]: %v", err)
	}
	dup1, err := ResolveStdioInvocation(exec, []string{pa, pa}, []int{1})
	if err != nil {
		t.Fatalf("resolve dup declared [1]: %v", err)
	}
	if dup0.Digest == dup1.Digest {
		t.Fatalf("P1: same-path declared position must affect the digest; got %q for both", dup0.Digest)
	}
}

// F. Payload mutation: changing declared entry payload contents must change
// the digest under the framed serialization (preserves the round-4 property).
func TestFramingPayloadMutationChangesDigest(t *testing.T) {
	exec := writeRunner(t)
	payload := writePayload(t, "server.js", "v1")

	before, err := ResolveStdioInvocation(exec, []string{payload}, []int{0})
	if err != nil {
		t.Fatalf("resolve v1: %v", err)
	}
	if err := os.WriteFile(payload, []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	after, err := ResolveStdioInvocation(exec, []string{payload}, []int{0})
	if err != nil {
		t.Fatalf("resolve v2: %v", err)
	}
	if before.Digest == after.Digest {
		t.Fatalf("P1: declared payload mutation must change the digest; got %q for both", before.Digest)
	}
}

// G. Determinism: the same executable, args, declared positions, and payload
// contents must produce the same digest across repeated resolution.
func TestFramingDeterministic(t *testing.T) {
	exec := writeRunner(t)
	entry := writePayload(t, "server.js", "serve stable")
	args := []string{entry, "--flag", "value"}

	want, err := ResolveStdioInvocation(exec, args, []int{0})
	if err != nil {
		t.Fatalf("resolve baseline: %v", err)
	}
	for i := 0; i < 3; i++ {
		got, err := ResolveStdioInvocation(exec, args, []int{0})
		if err != nil {
			t.Fatalf("resolve repeat %d: %v", i, err)
		}
		if got.Digest != want.Digest {
			t.Fatalf("P1: resolution must be deterministic; baseline=%q repeat=%q", want.Digest, got.Digest)
		}
	}
}

// Empty data is still a distinct field: an invocation with no args must
// differ from one whose only arg is empty.
func TestFramingEmptyArgumentDistinct(t *testing.T) {
	exec := writeRunner(t)
	noArgs, err := ResolveStdioInvocation(exec, nil, nil)
	if err != nil {
		t.Fatalf("resolve no args: %v", err)
	}
	emptyArg, err := ResolveStdioInvocation(exec, []string{""}, nil)
	if err != nil {
		t.Fatalf("resolve empty arg: %v", err)
	}
	if noArgs.Digest == emptyArg.Digest {
		t.Fatal("P1: empty argument must be a distinct component; got same digest")
	}
}
