// Package incidentbundle defines Visor Incident Bundle v0.1: a small,
// proof-quality record tying one authorization/execution episode together:
//
//	principal → delegation → authority → proposed action → policy decision
//	→ runtime execution → external effect → resulting state → propagation.
//
// Design constraints (see docs/incident-bundle.md):
//   - Additive only. Enforcement lives in policy/proxy; the audit logger owns
//     the live hash-chained JSONL stream. A bundle is a sealed, portable
//     excerpt: hash-linked events plus a signed manifest.
//   - No new crypto. Event chaining mirrors internal/audit (sha256 over the
//     record with Hash blanked, PrevHash carried); the manifest signature is
//     ed25519 via internal/signer interfaces, same as internal/receipt.
//   - Payloads stored in a bundle are already redacted. This package never
//     sees raw arguments; callers redact with internal/redaction first and
//     record which patterns applied.
package incidentbundle

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// SpecVersion is the bundle schema version this package implements.
const SpecVersion = "0.1"

// Event kinds. The four stages the spec requires callers to distinguish are
// requested_action, policy_decision, runtime_attempt, and external_effect;
// state_delta and propagation complete the episode graph.
const (
	KindRequestedAction = "requested_action"
	KindPolicyDecision  = "policy_decision"
	KindRuntimeAttempt  = "runtime_attempt"
	KindExternalEffect  = "external_effect"
	KindStateDelta      = "state_delta"
	KindPropagation     = "propagation"
)

// Confirmation states for external effects. A policy decision must never
// treat unconfirmed as confirmed; see docs/incident-bundle.md.
const (
	ConfirmationUnconfirmed = "unconfirmed"
	ConfirmationConfirmed   = "confirmed"
)

// Event is one node in the episode graph. Payload is an opaque,
// already-redacted JSON object; PayloadHash binds it.
type Event struct {
	Seq            uint64         `json:"seq"`
	PrevHash       string         `json:"prev_hash"`
	Kind           string         `json:"kind"`
	Timestamp      int64          `json:"timestamp"`
	Principal      string         `json:"principal,omitempty"`
	Delegation     []string       `json:"delegation,omitempty"`
	AuthorityRef   string         `json:"authority_ref,omitempty"`
	Payload        map[string]any `json:"payload,omitempty"`
	PayloadHash    string         `json:"payload_hash"`
	RedactionNote  string         `json:"redaction_note,omitempty"`
	Confirmation   string         `json:"confirmation,omitempty"`
	EvidenceSource string         `json:"evidence_source,omitempty"`
	// Supersedes names the seq of the event this one upgrades. Only
	// confirmation upgrades use it (see checkEpisode).
	Supersedes *uint64 `json:"supersedes,omitempty"`
	Hash       string  `json:"hash"`
}

// Manifest seals the bundle. Signature covers every field except Signature
// itself, over the same canonical JSON encoding used for events.
type Manifest struct {
	BundleID    string `json:"bundle_id"`
	SpecVersion string `json:"spec_version"`
	CreatedAt   int64  `json:"created_at"`
	EventCount  uint64 `json:"event_count"`
	HeadHash    string `json:"head_hash"`
	PolicyHash  string `json:"policy_hash"`
	PolicyID    string `json:"policy_id,omitempty"`
	KeyID       string `json:"key_id"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

// Bundle is a sealed episode: ordered hash-linked events plus manifest.
type Bundle struct {
	Manifest Manifest `json:"manifest"`
	Events   []Event  `json:"events"`
}

// SigningKey is implemented by internal/signer.ApprovalSigner.
type SigningKey interface {
	Sign(data []byte) ([]byte, error)
	PublicKey() crypto.PublicKey
	KeyID() string
	Algorithm() string
}

// VerifyingKey is implemented by internal/signer.ApprovalVerifier.
type VerifyingKey interface {
	Verify(data []byte, signature []byte) error
	PublicKey() crypto.PublicKey
	KeyID() string
}

// New starts an empty bundle. policyHash binds the authorizing policy;
// bundleID must be unique per episode (caller-assigned, e.g. execution id).
func New(bundleID, policyHash string, createdAt int64) *Bundle {
	if createdAt == 0 {
		createdAt = time.Now().Unix()
	}
	return &Bundle{
		Manifest: Manifest{
			BundleID:    bundleID,
			SpecVersion: SpecVersion,
			CreatedAt:   createdAt,
			PolicyHash:  policyHash,
		},
	}
}

// Append links one event. Payload must already be redacted; payloadHash must
// equal sha256 over the canonical JSON of payload (enforced here).
func (b *Bundle) Append(kind string, timestamp int64, build func(*Event)) error {
	switch kind {
	case KindRequestedAction, KindPolicyDecision, KindRuntimeAttempt,
		KindExternalEffect, KindStateDelta, KindPropagation:
	default:
		return fmt.Errorf("unknown event kind %q", kind)
	}
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	prev := ""
	if n := len(b.Events); n > 0 {
		prev = b.Events[n-1].Hash
	}
	ev := Event{
		Seq:       uint64(len(b.Events)),
		PrevHash:  prev,
		Kind:      kind,
		Timestamp: timestamp,
	}
	if build != nil {
		build(&ev)
	}
	// Framing belongs to Append, not the builder: content fields
	// (principal, payload, …) are the builder's domain, but sequence,
	// linkage, timestamp, and the stage itself are restored so a hostile
	// or buggy callback can neither retarget the stage nor corrupt the
	// chain inputs. Unknown kinds are rejected outright.
	ev.Kind = kind
	ev.Seq = uint64(len(b.Events))
	if n := len(b.Events); n > 0 {
		ev.PrevHash = b.Events[n-1].Hash
	} else {
		ev.PrevHash = ""
	}
	ev.Timestamp = timestamp
	if ev.Payload != nil {
		sum, err := canonicalHash(ev.Payload)
		if err != nil {
			return fmt.Errorf("hash payload: %w", err)
		}
		if ev.PayloadHash != "" && ev.PayloadHash != sum {
			return fmt.Errorf("payload_hash mismatch: declared recording does not match payload")
		}
		ev.PayloadHash = sum
	} else if ev.PayloadHash == "" {
		return fmt.Errorf("event carries neither payload nor payload_hash")
	} else if !validDigest(ev.PayloadHash) {
		return fmt.Errorf("payload_hash is not a sha256 hex digest")
	}
	h, err := eventHash(ev)
	if err != nil {
		return fmt.Errorf("hash event: %w", err)
	}
	ev.Hash = h
	b.Events = append(b.Events, ev)
	b.Manifest.EventCount = uint64(len(b.Events))
	b.Manifest.HeadHash = h
	return nil
}

// Seal signs the manifest. Further Appends invalidate the signature until
// Seal is called again.
func (b *Bundle) Seal(key SigningKey) error {
	if key == nil {
		return fmt.Errorf("signing key is nil")
	}
	if len(b.Events) == 0 {
		return fmt.Errorf("cannot seal an empty bundle")
	}
	b.Manifest.KeyID = key.KeyID()
	b.Manifest.Algorithm = key.Algorithm()
	if pub, ok := key.PublicKey().(ed25519.PublicKey); ok {
		b.Manifest.PublicKey = hex.EncodeToString(pub)
	}
	b.Manifest.Signature = ""
	sig, err := key.Sign(manifestPayload(b.Manifest))
	if err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}
	b.Manifest.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify checks structure, hash linkage, payload bindings, and the manifest
// signature. It detects tampering (mutated bytes), truncation or dropped
// events, reordering, and wrong-key signatures. It does not check freshness,
// wall-clock policy, or semantic truth of payloads.
func (b *Bundle) Verify(key VerifyingKey) error {
	if b.Manifest.SpecVersion != SpecVersion {
		return fmt.Errorf("unsupported spec version %q", b.Manifest.SpecVersion)
	}
	if uint64(len(b.Events)) != b.Manifest.EventCount {
		return fmt.Errorf("event count %d does not match manifest %d", len(b.Events), b.Manifest.EventCount)
	}
	if err := checkEpisode(b.Events); err != nil {
		return err
	}
	prev := ""
	for i := range b.Events {
		ev := &b.Events[i]
		if ev.Seq != uint64(i) {
			return fmt.Errorf("event %d has seq %d", i, ev.Seq)
		}
		// Payload evidence must bind something: inline payloads rehash
		// here, hash-only references must be well-formed digests.
		if ev.Payload == nil {
			if ev.PayloadHash == "" {
				return fmt.Errorf("event %d carries neither payload nor payload_hash", i)
			}
			if !validDigest(ev.PayloadHash) {
				return fmt.Errorf("event %d: payload_hash is not a sha256 hex digest", i)
			}
		}
		if ev.PrevHash != prev {
			return fmt.Errorf("event %d breaks the hash chain", i)
		}
		if ev.Payload != nil {
			sum, err := canonicalHash(ev.Payload)
			if err != nil {
				return fmt.Errorf("event %d: hash payload: %w", i, err)
			}
			if ev.PayloadHash != sum {
				return fmt.Errorf("event %d: payload does not match payload_hash", i)
			}
		}
		h, err := eventHash(*ev)
		if err != nil {
			return fmt.Errorf("event %d: hash event: %w", i, err)
		}
		if ev.Hash != h {
			return fmt.Errorf("event %d: hash mismatch (tampered?)", i)
		}
		prev = ev.Hash
	}
	if len(b.Events) > 0 && b.Manifest.HeadHash != b.Events[len(b.Events)-1].Hash {
		return fmt.Errorf("manifest head hash does not match tip event")
	}
	if b.Manifest.Signature == "" {
		return fmt.Errorf("manifest is not signed")
	}
	if key == nil {
		return fmt.Errorf("verifying key is nil")
	}
	// Bind the signed metadata claims to the verifier before checking the
	// signature itself: otherwise a valid signature gets reported under the
	// wrong key or algorithm. Backends label their own Ed25519 variants
	// (e.g. ed25519-vault-transit); a reporting verifier must agree exactly
	// with the manifest, while a non-reporting verifier only accepts plain
	// ed25519 — unknown labels fail closed. Key ids bind unconditionally:
	// empty on either side rejects.
	if b.Manifest.KeyID == "" {
		return fmt.Errorf("manifest key id is empty")
	}
	if key.KeyID() == "" {
		return fmt.Errorf("verifier key id is empty")
	}
	type algorithmReporter interface{ Algorithm() string }
	if ak, ok := key.(algorithmReporter); ok && ak.Algorithm() != "" {
		if b.Manifest.Algorithm != ak.Algorithm() {
			return fmt.Errorf("manifest algorithm %q does not match verifier %q", b.Manifest.Algorithm, ak.Algorithm())
		}
	} else if b.Manifest.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", b.Manifest.Algorithm)
	}
	if key.KeyID() != b.Manifest.KeyID {
		return fmt.Errorf("verifier key id does not match manifest")
	}
	keyPub, ok := key.PublicKey().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("verifier key is not ed25519")
	}
	manifestPub, err := hex.DecodeString(b.Manifest.PublicKey)
	if err != nil || !ed25519.PublicKey(manifestPub).Equal(keyPub) {
		return fmt.Errorf("manifest public key does not match verifier")
	}
	sig, err := hex.DecodeString(b.Manifest.Signature)
	if err != nil {
		return fmt.Errorf("decode manifest signature: %w", err)
	}
	if err := key.Verify(manifestPayload(b.Manifest), sig); err != nil {
		return fmt.Errorf("manifest signature invalid: %w", err)
	}
	return nil
}

// Marshal renders the bundle as canonical JSON.
func (b *Bundle) Marshal() ([]byte, error) {
	return json.Marshal(b)
}

// Unmarshal parses a bundle. Numbers decode as json.Number (same convention
// as internal/mcp canonicalization) so large integers survive the
// marshal→unmarshal→verify round trip without float64 precision loss.
// Call Verify afterwards; parsing alone proves nothing.
func Unmarshal(data []byte) (*Bundle, error) {
	var b Bundle
	// encoding/json coerces invalid UTF-8 to U+FFFD, which would reproduce
	// signed hashes from byte-different input: strict consumers must never
	// see what lenient decoding normalized away.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("bundle is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// Strict struct decoding: unknown fields outside payload would
	// otherwise slip past every hash and signature below. Maps (payload)
	// stay open by design.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("unmarshal bundle: %w", err)
	}
	// A single Decode stops at the first JSON value; trailing bytes would
	// sit outside every hash and signature while the bundle still verifies.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("trailing data after bundle")
	}
	// encoding/json is last-wins on duplicate members while other
	// consumers are first-wins: reject duplicates at every object level
	// (including open payload maps) before trusting the shape. Matching is
	// case-sensitive here; struct-field folding is handled by exact-shape
	// validation below.
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	// Struct levels must use exact canonical spellings: encoding/json binds
	// fields case-insensitively, so BUNDLE_ID would otherwise alias
	// bundle_id for some consumers and not others. Key sets derive from
	// struct tags via reflection, so they cannot drift from the schema.
	if err := checkExactShape(data); err != nil {
		return nil, err
	}
	return &b, nil
}

// exactKeys returns the canonical JSON member names of a struct from its
// json tags.
func exactKeys[T any]() map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf((*T)(nil)).Elem()
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = true
	}
	return out
}

// requiredKeys returns the canonical members without `omitempty`: they
// must be present (zero values marshal back identically, so presence —
// not value — is what absence attacks remove).
func requiredKeys[T any]() map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf((*T)(nil)).Elem()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		if strings.Contains(opts, "omitempty") {
			continue
		}
		out[name] = true
	}
	return out
}

// checkExactShape requires every struct-level member to use its canonical
// spelling, and every mandatory member to be present. Payload maps stay
// open; everything else is schema-fixed.
func checkExactShape(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return fmt.Errorf("unmarshal bundle envelope: %w", err)
	}
	if err := checkMembers("bundle", top, exactKeys[Bundle](), requiredKeys[Bundle]()); err != nil {
		return err
	}
	manifestKeys := exactKeys[Manifest]()
	var manifest map[string]json.RawMessage
	if raw, ok := top["manifest"]; ok {
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return fmt.Errorf("unmarshal manifest envelope: %w", err)
		}
		if err := checkMembers("manifest", manifest, manifestKeys, requiredKeys[Manifest]()); err != nil {
			return err
		}
	}
	eventKeys := exactKeys[Event]()
	eventRequired := requiredKeys[Event]()
	var events []json.RawMessage
	if raw, ok := top["events"]; ok {
		if err := json.Unmarshal(raw, &events); err != nil {
			return fmt.Errorf("unmarshal events envelope: %w", err)
		}
		for i, eraw := range events {
			var em map[string]json.RawMessage
			if err := json.Unmarshal(eraw, &em); err != nil {
				return fmt.Errorf("unmarshal event %d envelope: %w", i, err)
			}
			if err := checkMembers(fmt.Sprintf("event %d", i), em, eventKeys, eventRequired); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkMembers rejects non-canonical spellings and absent mandatory members.
func checkMembers(where string, got map[string]json.RawMessage, exact, required map[string]bool) error {
	for k := range got {
		if !exact[k] {
			return fmt.Errorf("non-canonical %s member %q", where, k)
		}
	}
	for k := range required {
		if _, ok := got[k]; !ok {
			return fmt.Errorf("%s is missing required member %q", where, k)
		}
	}
	return nil
}

// rejectDuplicateKeys walks the raw document tracking member names per
// object; any repeat fails, since signers and verifiers would otherwise
// disagree on which value the hashes cover. Payload maps are included:
// openness to new keys is not openness to ambiguous ones.
func rejectDuplicateKeys(data []byte) error {
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []frame
	// afterValue marks the parent frame's next string as a key again.
	afterValue := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("scan bundle: %w", err)
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{object: true, expectKey: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, frame{})
			case ']', '}':
				stack = stack[:len(stack)-1]
				afterValue()
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				top := stack[len(stack)-1].keys
				if top[t] {
					return fmt.Errorf("duplicate member %q", t)
				}
				top[t] = true
				stack[len(stack)-1].expectKey = false
			} else {
				afterValue()
			}
		default:
			// Numbers, bools, null: complete values.
			afterValue()
		}
	}
}

// requiredStages is the v0.1 episode order. A proof-quality bundle must show
// every stage in order; state_delta and propagation ride along freely, and
// external_effect may repeat (confirmation upgrades are append-only new
// events per docs/incident-bundle.md).
var requiredStages = []string{
	KindRequestedAction,
	KindPolicyDecision,
	KindRuntimeAttempt,
	KindExternalEffect,
}

// knownKinds is every event kind spec v0.1 admits: the four required
// stages plus the two documented auxiliary kinds.
var knownKinds = map[string]bool{
	KindRequestedAction: true,
	KindPolicyDecision:  true,
	KindRuntimeAttempt:  true,
	KindExternalEffect:  true,
	KindStateDelta:      true,
	KindPropagation:     true,
}

func checkEpisode(events []Event) error {
	need := 0
	// Targets consumed by confirmation upgrades: each unconfirmed effect
	// upgrades at most once, so a second confirmed repeat naming the same
	// target is a double-spend, not an upgrade.
	consumed := map[uint64]bool{}
	for i, ev := range events {
		if !knownKinds[ev.Kind] {
			return fmt.Errorf("unknown event kind %q", ev.Kind)
		}
		rank := -1
		for i, k := range requiredStages {
			if ev.Kind == k {
				rank = i
				break
			}
		}
		if rank < 0 {
			if ev.Supersedes != nil {
				return fmt.Errorf("supersedes is only valid on a confirmation upgrade")
			}
			continue
		}
		if ev.Kind == KindExternalEffect {
			if ev.Confirmation != ConfirmationConfirmed && ev.Confirmation != ConfirmationUnconfirmed {
				return fmt.Errorf("external_effect requires confirmation %q or %q", ConfirmationConfirmed, ConfirmationUnconfirmed)
			}
		}
		if rank != need {
			// Only genuine confirmation upgrades are allowed after
			// completion: the repeat must be confirmed, name the
			// unconfirmed effect it upgrades via supersedes, and that
			// target must still be unconfirmed and unconsumed. Anything
			// else out of position — premature, repeated, or regressed —
			// breaks proof quality.
			if need == len(requiredStages) && ev.Kind == KindExternalEffect &&
				ev.Confirmation == ConfirmationConfirmed && validUpgradeTarget(events, i, ev, consumed) {
				consumed[*ev.Supersedes] = true
				continue
			}
			if need >= len(requiredStages) {
				return fmt.Errorf("episode already complete: unexpected %q", ev.Kind)
			}
			return fmt.Errorf("episode out of order: got %q, want required stage %q", ev.Kind, requiredStages[need])
		}
		// Supersedes exists exclusively for the upgrade branch above: a
		// first effect, a required stage, or an auxiliary event carrying
		// it encodes an unvalidated supersession edge.
		if ev.Supersedes != nil {
			return fmt.Errorf("supersedes is only valid on a confirmation upgrade")
		}
		need++
	}
	if need < len(requiredStages) {
		return fmt.Errorf("episode incomplete: missing required stage %q", requiredStages[need])
	}
	return nil
}

// validUpgradeTarget reports whether events[i] (a confirmed post-completion
// external_effect) explicitly upgrades a still-unconfirmed earlier effect
// that no previous upgrade has consumed.
func validUpgradeTarget(events []Event, i int, ev Event, consumed map[uint64]bool) bool {
	if ev.Supersedes == nil {
		return false
	}
	target := *ev.Supersedes
	if target >= uint64(i) {
		return false
	}
	if consumed[target] {
		return false
	}
	prev := events[target]
	if prev.Seq != target {
		return false
	}
	return prev.Kind == KindExternalEffect && prev.Confirmation == ConfirmationUnconfirmed
}

// validDigest reports whether s is a lowercase sha256 hex digest.
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32
}

func eventHash(ev Event) (string, error) {
	ev.Hash = ""
	data, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func manifestPayload(m Manifest) []byte {
	m.Signature = ""
	data, _ := json.Marshal(m)
	return data
}

func canonicalHash(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
