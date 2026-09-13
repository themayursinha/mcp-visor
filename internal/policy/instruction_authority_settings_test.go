package policy

import "testing"

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
	on, err := Load([]byte("version: \"1.0\"\nsettings:\n  instruction_authority_continuity: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !on.Settings.InstructionAuthorityContinuity {
		t.Fatal("exact YAML key must set only this bool")
	}
	if on.Settings.CapabilityEval {
		t.Fatal("instruction_authority_continuity is not an alias for capability_accounting")
	}
}

func TestInstructionAuthorityContinuitySetDefaultsDoesNotEnable(t *testing.T) {
	p := &Policy{}
	p.SetDefaults()
	if p.Settings.InstructionAuthorityContinuity {
		t.Fatal("SetDefaults must not enable instruction_authority_continuity")
	}
}
