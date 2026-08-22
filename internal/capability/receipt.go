// Package capability: narrow capability-accumulation accounting.
// Default NoopEvaluator; opt-in via config flag. Deterministic, stdlib-only.
//
// receipt.go — canonical hash-linked receipt types (Receipt, PauseReceipt),
// strict JSONL Decode/Encode, hashing, sealing, and chain validation,
// mirroring internal/audit semantics (CDR CD-6).
package capability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

type EnvelopeState struct {
	State string `json:"state"`
}

// Step is one canonical, typed, REDACTED observation of a mediated tool call.
// The proxy constructs it AFTER redaction; it never carries raw secrets.
// Field declaration order is the canonical JSON order.
type Step struct {
	SessionID string            `json:"session_id"`
	StepID    int               `json:"step_id"` // strictly increasing per session; <= 0 → error
	Tool      string            `json:"tool"`
	Args      map[string]string `json:"args,omitempty"` // redacted typed args

	// Structured observation fields (canonical forms, §7.3).
	Path          string     `json:"path,omitempty"`           // mediated file tool path, if any
	Executable    string     `json:"executable,omitempty"`     // mediated exec tool name (filepath.Base), if any
	DestIP        netip.Addr `json:"dest_ip,omitempty"`        // mediated network destination, if any (zero = none)
	DestHost      string     `json:"dest_host,omitempty"`      // mediated hostname, if any (lowercased, trailing dot stripped)
	Result        string     `json:"result,omitempty"`         // mediated tool result string (scanned for markers)
	ArtifactMagic string     `json:"artifact_magic,omitempty"` // mediated byte fingerprint: "ELF" | "PE" | ""

	Declared     DeclaredAuthority `json:"declared"`
	Effect       string            `json:"effect,omitempty"`        // host_exec | net_egress | file_access | canary_access | ""
	EffectTarget string            `json:"effect_target,omitempty"` // raw effect target BEFORE canonicalization
	Primitive    string            `json:"primitive,omitempty"`     // declared capability primitive (declare event, CDR EventDeclare)
	Signals      []Signal          `json:"signals,omitempty"`       // extracted during Eval; may be pre-populated by the proxy
}

// DeclaredAuthority is the envelope + intent. Validation: on an opted-in
// session, Target and WorkspaceRoot are REQUIRED; missing → error.
type DeclaredAuthority struct {
	Target              string         `json:"target"`
	Network             []netip.Prefix `json:"network,omitempty"` // declared network envelope (optional; empty = no declared egress)
	Host                string         `json:"host,omitempty"`    // declared host (optional)
	WorkspaceRoot       string         `json:"workspace_root"`
	DeclaredExecutables []string       `json:"declared_executables,omitempty"` // declared executable base names (optional; empty = no declared exec)
	Intent              string         `json:"intent,omitempty"`
}

// RequiredProof names the fresh authorization demanded on PAUSE. Null on ALLOW.
type RequiredProof struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// Signal is a typed observation extracted from one step.
type Signal struct {
	Kind          string `json:"kind"`
	Observation   string `json:"observation"`
	EvidenceLevel string `json:"evidence_level"` // declared_only | artifact | runtime_marker | boundary_request
	SourceDigest  string `json:"source_digest"`  // SHA-256 of the source observation (redacted form)
}

// ProvisionalCapability is the machine-readable declared primitive when
// declared intent has not been confirmed (D1/CD-3). Nil (field omitted)
// when no primitive is declared.
type ProvisionalCapability struct {
	Capability    string `json:"capability"`
	Confirmation  string `json:"confirmation"`
	EvidenceLevel string `json:"evidence_level"`
}

// Receipt is one canonical hash-linked JSONL object. Field declaration order
// is the JSON field order (CD-6). Hash covers the canonical JSON of the
// receipt with Hash cleared (mirrors CDR Encode() and audit RecordHash).
type Receipt struct {
	ReceiptVersion            int                    `json:"receipt_version"`
	SessionID                 string                 `json:"session_id"`
	StepID                    int                    `json:"step_id"`
	DeclaredAuthority         DeclaredAuthority      `json:"declared_authority"`
	Signals                   []Signal               `json:"signals"`
	CapabilityBefore          []string               `json:"capability_before"`
	CapabilityDelta           []string               `json:"capability_delta"`
	CapabilityAfter           []string               `json:"capability_after"`
	ObservedCapability        string                 `json:"observed_capability"`
	NominalPermissionsChanged bool                   `json:"nominal_permissions_changed"`
	EffectiveAuthorityChanged bool                   `json:"effective_authority_changed"`
	EnvelopeBefore            EnvelopeState          `json:"envelope_before"`
	EnvelopeAfter             EnvelopeState          `json:"envelope_after"`
	EnvelopeTransition        string                 `json:"envelope_transition"`
	Decision                  string                 `json:"decision"` // ALLOW | PAUSE_REQUIRE_NEW_PROOF
	Reason                    string                 `json:"reason"`
	RequiredProof             *RequiredProof         `json:"required_proof"`
	PrevHash                  string                 `json:"prev_hash"`
	Hash                      string                 `json:"hash"`
	ProvisionalCapability     *ProvisionalCapability `json:"provisional_capability,omitempty"`
	CapabilityConfirmation    string                 `json:"-"`
}

// PauseReceipt is the fail-closed artifact the proxy MUST emit (or return to
// the policy layer) when Eval returns an error on an opted-in session: a
// PAUSE_REQUIRE_NEW_PROOF receipt with ReasonEvaluatorError. It is the
// adapter's error-to-pause mapping contract (§7.2): an evaluator error is
// never a silent allow.
//
// Rev 7 (reviewer run 183): the receipt carries ONLY a stable, safe
// ErrorCode — never raw/untrusted error detail. Raw values that the error
// path interpolates (targets, hosts, paths) are redaction-before-receipt:
// the durable artifact must not leak secrets through the error string.
type PauseReceipt struct {
	ReceiptVersion int    `json:"receipt_version"`
	SessionID      string `json:"session_id"`
	StepID         int    `json:"step_id"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	ErrorCode      string `json:"error_code,omitempty"` // stable, safe category (Rev 7); NEVER raw detail
	Detail         string `json:"detail,omitempty"`     // reserved; must be populated only with pre-redacted safe text (Rev 7: unused)
	PrevHash       string `json:"prev_hash"`
	Hash           string `json:"hash"`
}

// ErrorCode values are stable, safe categories for the durable error-to-pause
// artifact. They are intentionally NOT derived from raw values: the same
// failure class always yields the same code so downstream alerting and
// deduplication are deterministic, and no secret-shaped input can ever appear
// in the receipt (reviewer run 183).
const (
	ErrorCodeInvalidStep = "evaluator_invalid_step"
	ErrorCodeInternal    = "evaluator_internal"
)

// ClassifyError maps an evaluator error to its stable error code. Nil errors
// (a caller misuse the adapter must survive) map to ErrorCodeInternal. Any
// wrapped ErrInvalidStep maps to ErrorCodeInvalidStep; unknown errors map to
// ErrorCodeInternal (safe default, still PAUSE).
func ClassifyError(err error) string {
	if err == nil {
		return ErrorCodeInternal
	}
	if errors.Is(err, ErrInvalidStep) {
		return ErrorCodeInvalidStep
	}
	return ErrorCodeInternal
}

// NewPauseReceipt builds a sealed pause receipt for the failed step. The
// proxy chooses the prev_hash (the session's last known receipt hash, or
// GenesisPrevHash for the first step); if it does not have one, it MUST
// block/pause rather than seal an unattributable chain.
//
// Rev 7 (reviewer run 183): a nil err is tolerated (classified as
// ErrorCodeInternal) — the public failure path must never panic. Raw error
// text is NEVER copied into the receipt; only the stable ErrorCode is.
func NewPauseReceipt(sessionID string, stepID int, prevHash string, err error) (*PauseReceipt, error) {
	if prevHash == "" {
		return nil, fmt.Errorf("%w: no prev hash for pause receipt", ErrInvalidStep)
	}
	r := &PauseReceipt{
		ReceiptVersion: ReceiptVersion,
		SessionID:      sessionID,
		StepID:         stepID,
		Decision:       DecisionPauseRequireProof,
		Reason:         ReasonEvaluatorError,
		ErrorCode:      ClassifyError(err),
		PrevHash:       prevHash,
	}
	if err := r.Seal(prevHash); err != nil {
		return nil, err
	}
	return r, nil
}

// Seal sets PrevHash then computes and sets Hash, returning the sealed
// receipt. It mirrors CDR Receipt.Encode plus mcp-visor RecordHash.
func (r *Receipt) Seal(prevHash string) error {
	if prevHash == "" {
		return fmt.Errorf("%w: empty prev_hash", ErrInvalidStep)
	}
	r.PrevHash = prevHash
	h, err := HashReceipt(*r)
	if err != nil {
		return err
	}
	r.Hash = h
	return nil
}

// Seal is the PauseReceipt variant.
func (r *PauseReceipt) Seal(prevHash string) error {
	if prevHash == "" {
		return fmt.Errorf("%w: empty prev_hash", ErrInvalidStep)
	}
	r.PrevHash = prevHash
	h, err := HashPauseReceipt(*r)
	if err != nil {
		return err
	}
	r.Hash = h
	return nil
}

// HashReceipt returns the canonical hash of r: "sha256:" + lowercase hex of
// SHA-256 over the canonical JSON of r with Hash cleared (CD-6).
func HashReceipt(r Receipt) (string, error) {
	r.Hash = ""
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("capability hash marshal: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// HashPauseReceipt is the PauseReceipt variant of HashReceipt.
func HashPauseReceipt(r PauseReceipt) (string, error) {
	r.Hash = ""
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("capability pause hash marshal: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Encode returns the canonical JSONL line (one object, trailing newline)
// with the Hash field populated. It is the serialized form that goes into
// the sibling capability receipt stream.
func (r *Receipt) Encode() ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("capability encode: %w", err)
	}
	return append(data, '\n'), nil
}

// Decode parses exactly ONE canonical JSONL object. It rejects: unknown
// receipt versions, missing chain-critical fields (session_id, step_id,
// decision, prev_hash, hash), leading/trailing whitespace, trailing bytes
// (a second object, appended JSON, or garbage), and duplicate keys within
// the object. Re-encoding the decoded receipt MUST produce the exact input
// bytes (canonical form; tested). This closes the parser-differential
// acceptance gap (reviewer run 179).
func Decode(data []byte) (*Receipt, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrInvalidStep)
	}
	// Permit exactly one optional trailing newline (the canonical JSONL
	// line terminator); any other trailing byte (including a second object
	// or a trailing JSON value) is rejected. Leading whitespace is rejected
	// (the canonical line starts with '{').
	if data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty input after line terminator", ErrInvalidStep)
	}
	if data[0] != '{' {
		return nil, fmt.Errorf("%w: leading whitespace or non-object start", ErrInvalidStep)
	}
	// Byte-exact canonical line check: exactly one object plus optional
	// single trailing newline. Rejects trailing whitespace beyond the line
	// terminator, a second object, and appended garbage.
	if !isCanonicalLine(data) {
		return nil, fmt.Errorf("%w: non-canonical line (trailing data or whitespace)", ErrInvalidStep)
	}
	// Reject duplicate keys: a full pass over the object tokens before
	// decoding. encoding/json silently keeps the LAST occurrence, which
	// would be a parser-differential; the contract forbids it.
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, err
	}
	var r Receipt
	cr := &countingReader{r: bytes.NewReader(data)}
	dec := json.NewDecoder(cr)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidStep, err)
	}
	// Strict single-object: after the first value the decoder must be at EOF
	// AND have consumed the entire input. The counting reader catches bytes
	// the decoder never read; the final Token() catches a second object.
	// Trailing whitespace beyond the single permitted line terminator is
	// rejected by the byte-exactness check below (the canonical line is
	// exactly one JSON object plus one optional '\n').
	if err := ensureEOF(dec, cr, int64(len(data))); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidStep, err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	// Rev 6 (reviewer run 181): the canonical form is byte-exact. Re-encode
	// the decoded receipt and require BYTE-IDENTICAL output (modulo the
	// single optional line terminator, which Encode always emits). This
	// rejects non-canonical INTERNAL whitespace (a space inserted after a
	// comma or colon), key reordering, and any other divergence the decoder
	// would otherwise accept — closing the parser-differential acceptance
	// gap.
	canon, err := r.Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: re-encode: %v", ErrInvalidStep, err)
	}
	canon = bytes.TrimSuffix(canon, []byte("\n"))
	if !bytes.Equal(canon, data) {
		return nil, fmt.Errorf("%w: non-canonical receipt (re-encode differs)", ErrInvalidStep)
	}
	return &r, nil
}

// countingReader wraps a bytes.Reader so the decoder can report exactly how
// many input bytes it consumed (used by ensureEOF for strict trailing-input
// rejection).
type countingReader struct {
	r *bytes.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// isCanonicalLine reports whether data is EXACTLY one JSON object with
// nothing before it and nothing after it except an optional single trailing
// newline. The canonical receipt line is `{...}\n`; any other byte (space,
// tab, CR, a second object, garbage) violates the JSONL contract.
func isCanonicalLine(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return false
	}
	if data[0] != '{' {
		return false
	}
	// No trailing whitespace: after the object's closing '}' there must be
	// nothing (we already stripped one trailing '\n').
	return data[len(data)-1] == '}'
}

// checkNoDuplicateKeys scans the canonical JSON object and rejects any
// object containing a duplicated key. encoding/json silently keeps the LAST
// occurrence of a duplicate key, which would be a parser-differential the
// contract forbids (reviewer run 179). A JSON string is a KEY iff it is
// followed (after whitespace) by ':'; value strings are followed by ',',
// '}', or ']'. Depth is tracked per open '{'.
func checkNoDuplicateKeys(data []byte) error {
	var stack []map[string]bool
	i, n := 0, len(data)
	for i < n {
		c := data[i]
		switch c {
		case '{':
			stack = append(stack, map[string]bool{})
			i++
		case '}':
			if len(stack) == 0 {
				return fmt.Errorf("%w: unbalanced object", ErrInvalidStep)
			}
			stack = stack[:len(stack)-1]
			i++
		case '"':
			start := i
			i++
			for i < n && data[i] != '"' {
				if data[i] == '\\' {
					i++
				}
				i++
			}
			if i >= n {
				return fmt.Errorf("%w: unterminated string", ErrInvalidStep)
			}
			i++ // closing quote
			// Key iff followed by ':' after whitespace.
			j := i
			for j < n && (data[j] == ' ' || data[j] == '	' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < n && data[j] == ':' {
				if len(stack) == 0 {
					return fmt.Errorf("%w: key outside object", ErrInvalidStep)
				}
				key := string(data[start:i])
				if stack[len(stack)-1][key] {
					return fmt.Errorf("%w: duplicate key %q", ErrInvalidStep, key)
				}
				stack[len(stack)-1][key] = true
			}
		case '[', ']', ',', ':':
			i++
		case ' ', '	', '\n', '\r':
			i++
		default:
			// number / true / false / null literal — skip to next structural char.
			for i < n && data[i] != ',' && data[i] != '}' && data[i] != ']' &&
				data[i] != '{' && data[i] != '[' && data[i] != ':' && data[i] != '"' &&
				data[i] != ' ' && data[i] != '	' && data[i] != '\n' && data[i] != '\r' {
				i++
			}
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("%w: unclosed object", ErrInvalidStep)
	}
	return nil
}

// ensureEOF asserts the decoder consumed the ENTIRE input: the counting
// reader must report all bytes consumed and the decoder must be at EOF. This
// rejects trailing whitespace, a second object, appended JSON, and garbage
// after the single receipt object (reviewer run 179).
func ensureEOF(dec *json.Decoder, cr *countingReader, total int64) error {
	if cr.n != total {
		return fmt.Errorf("%w: trailing data after receipt object (%d/%d bytes consumed)", ErrInvalidStep, cr.n, total)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%w: trailing data after receipt object", ErrInvalidStep)
		}
		return err
	}
	return nil
}

// Validate checks the canonical invariants of a decoded receipt: version,
// chain-critical fields, and hash re-derivation.
func (r *Receipt) Validate() error {
	if r.ReceiptVersion != ReceiptVersion {
		return fmt.Errorf("%w: unknown receipt version %d", ErrInvalidStep, r.ReceiptVersion)
	}
	if r.SessionID == "" {
		return fmt.Errorf("%w: empty session_id", ErrInvalidStep)
	}
	if r.StepID <= 0 {
		return fmt.Errorf("%w: non-positive step_id", ErrInvalidStep)
	}
	if r.Decision != DecisionAllow && r.Decision != DecisionPauseRequireProof {
		return fmt.Errorf("%w: unknown decision %q", ErrInvalidStep, r.Decision)
	}
	if r.PrevHash == "" || r.Hash == "" {
		return fmt.Errorf("%w: chain fields missing", ErrInvalidStep)
	}
	want, err := HashReceipt(*r)
	if err != nil {
		return err
	}
	if r.Hash != want {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidStep)
	}
	return nil
}
