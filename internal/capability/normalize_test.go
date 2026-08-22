package capability

import (
	"os"
	"strings"
	"testing"
)

// normalize_test.go — canonical identity/normalization helpers: path,
// hostname (RFC 1123), CIDR, executable, and declared-authority validation.

func TestCanonicalCIDR(t *testing.T) {
	if _, err := CanonicalCIDR("10.0.0.5/24"); err == nil {
		t.Fatalf("host bits in CIDR must be rejected")
	}
	p, err := CanonicalCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("valid CIDR rejected: %v", err)
	}
	if p.String() != "10.0.0.0/24" {
		t.Fatalf("cidr not normalized: %s", p.String())
	}
}

// Fail-closed boundary gap (reviewer run 175): a malformed EffectTarget is an
// error even when DestIP is valid. The raw target and structured field must
// agree; ambiguity fails closed.

func TestCanonicalHostStrictValidation(t *testing.T) {
	bad := []string{
		"-bad.example", // leading hyphen (reviewer's case)
		"bad-.example", // trailing hyphen (reviewer's case)
		"bad..example", // empty label
		".bad.example", // leading empty label
		"under_score.example",
		"a" + strings.Repeat("b", 63) + ".example", // label 64 chars
		strings.Repeat("a", 254),                   // total 254 chars
	}
	for _, s := range bad {
		if _, err := CanonicalHostIsValid(s); err == nil {
			t.Fatalf("host %q must be rejected", s)
		}
	}
	// Trailing dot and case normalization.
	h, err := CanonicalHostIsValid("Prod-Host.")
	if err != nil {
		t.Fatalf("valid host rejected: %v", err)
	}
	if h != "prod-host" {
		t.Fatalf("canonical host = %q, want %q", h, "prod-host")
	}
	// Valid names pass (including a trailing dot, which is normalized).
	for _, s := range []string{"example.com", "prod-host", "a", "x-y.z" + strings.Repeat("a", 60), "bad.example."} {
		if _, err := CanonicalHostIsValid(s); err != nil {
			t.Fatalf("valid host %q rejected: %v", s, err)
		}
	}
}

// 4b. A declared host with a non-canonical spelling in ValidateAuthority
// passes validation (it is validated then normalized), and a malformed
// declared host (leading hyphen) fails closed.

func TestCanonicalPathContainment(t *testing.T) {
	ws := t.TempDir()
	if _, err := CanonicalPath(ws+"/poc.js", ws, false); err != nil {
		t.Fatalf("in-workspace path rejected: %v", err)
	}
	if _, err := CanonicalPath("/etc/passwd", ws, false); err == nil {
		t.Fatalf("outside-workspace path must be rejected")
	}
}

// Canonicalization: a symlink inside the workspace pointing outside is
// rejected when the target exists (EvalSymlinks containment).

func TestCanonicalPathSymlinkEscape(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	link := ws + "/escape"
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CanonicalPath(link+"/poc.js", ws, true); err == nil {
		t.Fatalf("symlink escape outside workspace must be rejected")
	}
}

// Canonicalization: CIDR with host bits rejected; normalized prefix accepted.

func TestRev6CanonicalHostRejectsIPLiteral(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.7", "2001:db8::1", "::1", "0.0.0.0"} {
		if _, err := CanonicalHostIsValid(s); err == nil {
			t.Fatalf("IP literal %q must be rejected as a hostname", s)
		}
	}
	// A legitimate numeric-looking label is still a valid hostname (single
	// label "12345" is not an IP literal — no dots — and is RFC 1123 legal).
	if _, err := CanonicalHostIsValid("example.com"); err != nil {
		t.Fatalf("valid hostname rejected: %v", err)
	}
}

// 4. Decode must reject non-canonical INTERNAL JSON whitespace: a line with
// a space inserted after a comma (or anywhere inside the object) is not the
// canonical byte stream and must fail — even though encoding/json parses it.
// The contract requires byte-identical re-encoding of the canonical form.

func TestValidateAuthorityHostNormalization(t *testing.T) {
	// Non-canonical spelling is VALID (normalized later by Eval).
	if err := ValidateAuthority(DeclaredAuthority{
		Target: "t", WorkspaceRoot: "/ws", Host: "Prod-Host.",
	}); err != nil {
		t.Fatalf("non-canonical but valid host must pass validation: %v", err)
	}
	// Malformed host fails closed.
	if err := ValidateAuthority(DeclaredAuthority{
		Target: "t", WorkspaceRoot: "/ws", Host: "-bad.example",
	}); err == nil {
		t.Fatalf("malformed declared host must fail closed")
	}
}

func TestValidateAuthorityMalformedHostAndExecutables(t *testing.T) {
	bad := []DeclaredAuthority{
		{Target: "t", WorkspaceRoot: "/ws", Host: "bad host!"},
		{Target: "t", WorkspaceRoot: "/ws", Host: ".bad"},
		{Target: "t", WorkspaceRoot: "/ws", DeclaredExecutables: []string{"/bin/bash"}},
		{Target: "t", WorkspaceRoot: "/ws", DeclaredExecutables: []string{""}},
		{Target: "t", WorkspaceRoot: "/ws", DeclaredExecutables: []string{"."}},
	}
	for i, da := range bad {
		if err := ValidateAuthority(da); err == nil {
			t.Fatalf("case %d: malformed declared host/executable must error", i)
		}
	}
	// Valid authority passes.
	ok := DeclaredAuthority{
		Target: "t", WorkspaceRoot: "/ws", Host: "Prod-Host.",
		DeclaredExecutables: []string{"bash"},
	}
	if err := ValidateAuthority(ok); err != nil {
		t.Fatalf("valid authority rejected: %v", err)
	}
}

// Receipt schema: the receipt matches CDR exactly — nested envelope objects
// and the provisional_capability field when a primitive is declared.
