package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestInstructionAuthorityContinuityDefaultsOff(t *testing.T) {
	if DefaultPolicy().Settings.InstructionAuthorityContinuity {
		t.Fatal("DefaultPolicy must leave instruction_authority_continuity false")
	}
	omitted, err := Load([]byte("version: \"1.0\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if omitted.Settings.InstructionAuthorityContinuity {
		t.Fatal("omitted instruction_authority_continuity must stay false")
	}
	off, err := Load([]byte("version: \"1.0\"\nsettings:\n  instruction_authority_continuity: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if off.Settings.InstructionAuthorityContinuity {
		t.Fatal("false must stay false")
	}
}

func TestInstructionAuthorityContinuityParsesTrue(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString(pub)
	on, err := Load([]byte("version: \"1.0\"\nsettings:\n  instruction_authority_continuity: true\n  instruction_authority_ed25519_public_keys:\n    issuer-2026-09: " + enc + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !on.Settings.InstructionAuthorityContinuity {
		t.Fatal("exact YAML key must set only this bool")
	}
	if on.Settings.CapabilityEval {
		t.Fatal("instruction_authority_continuity is not an alias for capability_accounting")
	}
	if on.Settings.InstructionAuthorityEd25519PublicKeys["issuer-2026-09"] != enc {
		t.Fatal("public key must parse")
	}
}

func TestInstructionAuthorityContinuitySetDefaultsDoesNotEnable(t *testing.T) {
	p := &Policy{}
	p.SetDefaults()
	if p.Settings.InstructionAuthorityContinuity {
		t.Fatal("SetDefaults must not enable instruction_authority_continuity")
	}
}

func TestInstructionAuthorityPublicKeysParseAndValidate(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString(pub)
	p, err := Load([]byte("version: \"1.0\"\nsettings:\n  instruction_authority_ed25519_public_keys:\n    rotate-old: " + enc + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Settings.InstructionAuthorityContinuity {
		t.Fatal("keys may be present while off")
	}
	if p.Settings.InstructionAuthorityEd25519PublicKeys["rotate-old"] != enc {
		t.Fatal("staged key missing")
	}
}

func TestInstructionAuthorityEnabledRequiresPublicKey(t *testing.T) {
	_, err := Load([]byte("version: \"1.0\"\nsettings:\n  instruction_authority_continuity: true\n"))
	if err == nil || !strings.Contains(err.Error(), "at least one key is required when instruction_authority_continuity is true") {
		t.Fatalf("err=%v", err)
	}
}

func TestInstructionAuthorityPublicKeyValidationRejectsInvalid(t *testing.T) {
	_, err := Load([]byte("version: \"1.0\"\nsettings:\n  instruction_authority_ed25519_public_keys:\n    \"bad id\": dGVzdA\n"))
	if err == nil || !strings.Contains(err.Error(), "invalid key id") {
		t.Fatalf("err=%v", err)
	}
	_, err = Load([]byte("version: \"1.0\"\nsettings:\n  instruction_authority_ed25519_public_keys:\n    ok: not-base64url\n"))
	if err == nil || !strings.Contains(err.Error(), "must be canonical unpadded base64url for a 32-byte Ed25519 public key") {
		t.Fatalf("err=%v", err)
	}
}
