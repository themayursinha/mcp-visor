package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// receipt_test.go — canonical hash-linked receipt schema, strict JSONL
// decode, sealing, and the pause-receipt error-to-pause contract.

func TestDecodeRoundTrip(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-16")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-16", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	line, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Hash != r.Hash || got.StepID != r.StepID || got.Decision != r.Decision {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, r)
	}
}

// Deterministic netip: declared network makes in-envelope egress ALLOW.

func TestDecodeStrictJSONL(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-35")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-35", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	line, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Canonical line decodes and re-encodes byte-identically.
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("canonical line decode: %v", err)
	}
	re, err := got.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(re, line) {
		t.Fatalf("re-encode not byte-identical: %q vs %q", re, line)
	}
	// Trailing appended object (reviewer's case: valid_line + {receipt_version:2}).
	trailing := append(append([]byte{}, line...), []byte(`{"receipt_version":2}`)...)
	if _, err := Decode(trailing); err == nil {
		t.Fatalf("Decode must reject trailing appended object")
	}
	// Leading whitespace.
	if _, err := Decode(append([]byte("  "), line...)); err == nil {
		t.Fatalf("Decode must reject leading whitespace")
	}
	// Trailing whitespace after the object (beyond the line terminator).
	if _, err := Decode(append(line, "  "...)); err == nil {
		t.Fatalf("Decode must reject trailing whitespace after line terminator")
	}
	// Duplicate key (reviewer's parser-differential case).
	dup := strings.Replace(string(line), `"session_id":"sess-35"`, `"session_id":"sess-35","session_id":"sess-35"`, 1)
	if _, err := Decode([]byte(dup)); err == nil {
		t.Fatalf("Decode must reject duplicate keys")
	}
}

// 3b. Strict JSONL: unknown receipt version is still rejected.

func TestDecodeStrictUnknownVersion(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-36")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-36", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := r.Encode()
	line = []byte(strings.Replace(string(line), `"receipt_version":1`, `"receipt_version":2`, 1))
	if _, err := Decode(line); err == nil {
		t.Fatalf("unknown receipt version must be rejected")
	}
}

// 4. Strict hostname validation: leading/trailing hyphens, empty labels,
// overlong labels/names, and underscores are rejected; trailing-dot and
// case normalization are applied; valid names pass.

func TestDecodeUnknownVersionRejected(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-15")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-15", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	line, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the version in the JSON and decode → must reject.
	line = []byte(strings.Replace(string(line), `"receipt_version":1`, `"receipt_version":2`, 1))
	if _, err := Decode(line); err == nil {
		t.Fatalf("unknown receipt version must be rejected")
	}
}

// Decode round-trip: a valid canonical line decodes and re-validates.

func TestPauseReceiptFailClosed(t *testing.T) {
	r, err := NewPauseReceipt("sess-18", 3, GenesisPrevHash, ErrInvalidStep)
	if err != nil {
		t.Fatalf("NewPauseReceipt: %v", err)
	}
	if r.Decision != DecisionPauseRequireProof || r.Reason != ReasonEvaluatorError {
		t.Fatalf("pause receipt must carry PAUSE + evaluator_error, got %s/%s", r.Decision, r.Reason)
	}
	if !strings.HasPrefix(r.Hash, "sha256:") {
		t.Fatalf("pause receipt hash missing prefix: %s", r.Hash)
	}
	// Determinism: same failure → same hash.
	r2, err := NewPauseReceipt("sess-18", 3, GenesisPrevHash, ErrInvalidStep)
	if err != nil {
		t.Fatal(err)
	}
	if r.Hash != r2.Hash {
		t.Fatalf("pause receipt not deterministic: %s vs %s", r.Hash, r2.Hash)
	}
	// No prev hash → error (never seal an unattributable chain).
	if _, err := NewPauseReceipt("sess-18", 3, "", ErrInvalidStep); err == nil {
		t.Fatalf("pause receipt without prev hash must error")
	}
}

// Signal extraction: all 8 signal kinds are produced across representative
// mediated observations, and SourceDigest is a sha256 digest. A single step
// has ONE effect, so boundary kinds 6–8 are exercised one step each.

func TestReceiptJSONSchemaAndHashCoverage(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-13")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-13", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	line, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		t.Fatalf("receipt is not JSON: %v", err)
	}
	for _, key := range []string{"receipt_version", "session_id", "step_id", "declared_authority", "signals", "capability_before", "capability_delta", "capability_after", "observed_capability", "envelope_before", "envelope_after", "envelope_transition", "decision", "reason", "required_proof", "prev_hash", "hash"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("receipt missing canonical key %q (keys: %v)", key, keysOf(raw))
		}
	}
	for _, bad := range []string{"ReceiptVersion", "SessionID", "PrevHash"} {
		if _, ok := raw[bad]; ok {
			t.Fatalf("receipt uses Go field name %q, want snake_case", bad)
		}
	}
	// Envelope states are nested objects (CDR exact schema).
	var envBefore map[string]string
	if err := json.Unmarshal(raw["envelope_before"], &envBefore); err != nil {
		t.Fatalf("envelope_before not an object: %v", err)
	}
	if envBefore["state"] != EnvelopeStateHigh {
		t.Fatalf("envelope_before.state = %q, want HIGH", envBefore["state"])
	}
	// Hash covers the canonical JSON with Hash cleared.
	r2 := *r
	r2.Hash = ""
	data, _ := json.Marshal(r2)
	sum := sha256.Sum256(data)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if r.Hash != want {
		t.Fatalf("hash mismatch: got %s want %s", r.Hash, want)
	}
}

// Hash-link: Seal produces a stable hash; re-sealing the same receipt with
// a different prior changes the hash (chain integrity).

func TestReceiptProvisionalFieldSerialized(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-28")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-28", StepID: 1, Tool: "plan",
		Primitive: "native_exec",
		Declared:  DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	line, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		t.Fatal(err)
	}
	var pc map[string]string
	if err := json.Unmarshal(raw["provisional_capability"], &pc); err != nil {
		t.Fatalf("provisional_capability not an object: %v", err)
	}
	if pc["capability"] != "native_exec" || pc["confirmation"] != "provisional" {
		t.Fatalf("provisional_capability = %v", pc)
	}
	// envelope_before/after are nested objects.
	for _, k := range []string{"envelope_before", "envelope_after"} {
		var eo map[string]string
		if err := json.Unmarshal(raw[k], &eo); err != nil {
			t.Fatalf("%s not an object: %v", k, err)
		}
		if eo["state"] == "" {
			t.Fatalf("%s.state missing", k)
		}
	}
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func sameCaps(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ===== Rev 5 closures (independent review run 179) =====

// 1. Host-exec partial authority: a declared executable set with NO declared
// host must NOT allow — host membership cannot be established → E5.
// (Reviewer's adversarial case: DeclaredExecutables=["bash"], no declared
// host, EffectTarget="bash", Executable="bash", DestHost="evil.example" →
// previously ALLOW; now PAUSE.)

func TestRev6DecodeRejectsInternalWhitespace(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r6-4")
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), Step{
		SessionID: "sess-r6-4", StepID: 1, Tool: "file_write",
		Effect: EffectFileAccess, EffectTarget: ws + "/poc.js",
		Declared: DeclaredAuthority{Target: "research-target", WorkspaceRoot: ws},
	}, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	line, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Insert a space after the FIRST comma — internal whitespace.
	idx := bytes.IndexByte(line, ',')
	if idx < 0 {
		t.Fatalf("canonical line has no comma: %q", line)
	}
	noncanonical := append([]byte{}, line[:idx+1]...)
	noncanonical = append(noncanonical, ' ')
	noncanonical = append(noncanonical, line[idx+1:]...)
	if _, err := Decode(noncanonical); err == nil {
		t.Fatalf("non-canonical internal whitespace must be rejected")
	}
	// Also reject a space after a colon (key-value separator).
	colon := bytes.Index(line, []byte(`"step_id":`))
	if colon < 0 {
		t.Fatalf("canonical line missing step_id: %q", line)
	}
	colonIdx := colon + len(`"step_id"`)
	noncanonical2 := append([]byte{}, line[:colonIdx]...)
	noncanonical2 = append(noncanonical2, ' ')
	noncanonical2 = append(noncanonical2, line[colonIdx:]...)
	if _, err := Decode(noncanonical2); err == nil {
		t.Fatalf("non-canonical whitespace after colon must be rejected")
	}
	// The canonical line still round-trips byte-identically.
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("canonical line decode: %v", err)
	}
	re, err := got.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(re, line) {
		t.Fatalf("re-encode not byte-identical: %q vs %q", re, line)
	}
}

func TestRev7PauseReceiptErrorCodeStableAndSafe(t *testing.T) {
	// Same failure class, different raw values → same stable code.
	a := fmt.Errorf("%w: host_exec target %q != structured executable", ErrInvalidStep, "bash")
	b := fmt.Errorf("%w: host_exec target %q != structured executable", ErrInvalidStep, "evil")
	ra, err := NewPauseReceipt("sess-r7-6", 1, GenesisPrevHash, a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := NewPauseReceipt("sess-r7-6", 1, GenesisPrevHash, b)
	if err != nil {
		t.Fatal(err)
	}
	if ra.ErrorCode != rb.ErrorCode {
		t.Fatalf("same failure class must map to same stable code: %q vs %q", ra.ErrorCode, rb.ErrorCode)
	}
	for _, v := range []string{a.Error(), b.Error(), "bash", "evil"} {
		if bytes.Contains(mustEncodePause(t, ra), []byte(v)) && v != "bash" && v != "evil" {
			t.Fatalf("raw error text leaked into pause receipt: %q", v)
		}
	}
	// A raw-value marker never appears in the durable artifact.
	if bytes.Contains(mustEncodePause(t, ra), []byte("evil")) {
		t.Fatalf("raw value leaked into pause receipt")
	}
}

func mustEncodePause(t *testing.T, r *PauseReceipt) []byte {
	t.Helper()
	line, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// Rev 8 (reviewer run 185): a MALFORMED observed DestHost on host_exec must
// be an evaluator error → PAUSE (ReasonEvaluatorError, stable error_code),
// NEVER classified as ordinary E5 — even when the optional authority is empty
// or only executables are declared. Rev 7 validated DestHost only inside the
// declared-host branch, so the early E5 branches
// (len(DeclaredExecutables)==0 / Declared.Host=="") classified a malformed
// observation as plain effect_outside_declared_envelope with no error. The
// Rev 8 hoist validates ANY populated observed DestHost before those
// branches. These tests reproduce the reviewer's exact two cases and assert
// the full error-to-pause mapping (errors.Is(err, ErrInvalidStep) AND
// NewPauseReceipt → ReasonEvaluatorError / ErrorCodeInvalidStep).

// 1a. Empty optional authority (no declared exec set, no declared host) +
// malformed observed DestHost → evaluator error → PAUSE, never ordinary E5.

func TestRev7PauseReceiptNilErrorNoPanic(t *testing.T) {
	r, err := NewPauseReceipt("sess-r7-2", 1, GenesisPrevHash, nil)
	if err != nil {
		t.Fatalf("nil error must produce a sealed pause receipt, got %v", err)
	}
	if r.Decision != DecisionPauseRequireProof || r.Reason != ReasonEvaluatorError {
		t.Fatalf("nil-error pause receipt must be PAUSE + evaluator_error, got %s/%s", r.Decision, r.Reason)
	}
	if r.ErrorCode == "" {
		t.Fatalf("nil-error pause receipt must carry a stable error code")
	}
}

// 3. The sealed receipt must NOT alias caller-owned memory. Rev 6
// ExtractSignals returned step.Signals directly and Eval stored that slice in
// the receipt before sealing — mutating the caller's slice changed the
// receipt contents without changing Hash (hash became stale). Eval must
// defensively copy the signal set before receipt construction/sealing.

func TestRev7PauseReceiptNoRawDetailLeak(t *testing.T) {
	secret := "sk-" + strings.Repeat("A", 48)
	rawErr := fmt.Errorf("%w: net_egress target %q does not match DestIP", ErrInvalidStep, secret)
	r, err := NewPauseReceipt("sess-r7-1", 1, GenesisPrevHash, rawErr)
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(line, []byte(secret)) {
		t.Fatalf("pause receipt leaks raw error detail: %s", line)
	}
	if r.ErrorCode == "" {
		t.Fatalf("pause receipt must carry a stable error code, got empty")
	}
	// The stable code must be deterministic across identical failures.
	r2, err := NewPauseReceipt("sess-r7-1", 1, GenesisPrevHash, rawErr)
	if err != nil {
		t.Fatal(err)
	}
	if r.ErrorCode != r2.ErrorCode || r.Hash != r2.Hash {
		t.Fatalf("error code / pause hash not deterministic: %s/%s vs %s/%s", r.ErrorCode, r.Hash, r2.ErrorCode, r2.Hash)
	}
}

// 2. A nil error must never panic the public error-to-pause path. Rev 6
// dereferenced err.Error() unconditionally.

func TestRev7SealedReceiptDefensiveSignalCopy(t *testing.T) {
	ws := t.TempDir()
	e, err := NewChainEvaluator("sess-r7-3")
	if err != nil {
		t.Fatal(err)
	}
	pre := []Signal{{
		Kind: SignalBoundaryHostExec, Observation: "host exec bash",
		EvidenceLevel: EvidenceBoundaryRequest, SourceDigest: "d1",
	}}
	step := Step{
		SessionID: "sess-r7-3", StepID: 1, Tool: "host_exec",
		Executable: "bash", Effect: EffectHostExec, EffectTarget: "bash",
		Declared: DeclaredAuthority{Target: "t", WorkspaceRoot: ws},
		Signals:  pre,
	}
	r, err := e.Eval(context.Background(), step, GenesisPrevHash)
	if err != nil {
		t.Fatal(err)
	}
	before, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the caller-owned slice AFTER Eval. The sealed receipt must be
	// unaffected (defensive copy) and its hash must still validate.
	pre[0].Observation = "MUTATED"
	after, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("sealed receipt mutated by caller-owned signal slice")
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("sealed receipt hash invalid after caller mutation: %v", err)
	}
}

// 4a. A malformed OBSERVED host must be an evaluator error (fail closed),
// never classified as ordinary E5. Rev 6 host-exec attribution only
// canonical-compared DestHost; DestHost="bad host!" was treated as a plain
// out-of-envelope pause (reason effect_outside_declared_envelope, no error),
// violating §5.1/§7.3 (malformed target/host → evaluator error →
// ReasonEvaluatorError).

func TestSealHashLink(t *testing.T) {
	r := &Receipt{
		ReceiptVersion: ReceiptVersion,
		SessionID:      "sess-14",
		StepID:         1,
		Decision:       DecisionAllow,
	}
	if err := r.Seal(GenesisPrevHash); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !strings.HasPrefix(r.Hash, "sha256:") {
		t.Fatalf("hash missing prefix: %s", r.Hash)
	}
	if r.PrevHash != GenesisPrevHash {
		t.Fatalf("prev hash not set: %s", r.PrevHash)
	}
}

// Decode rejects an unknown receipt version.
