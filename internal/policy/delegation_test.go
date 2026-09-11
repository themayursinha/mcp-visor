package policy

import (
	"strings"
	"testing"
)

func TestLintNegativeMaxSpawnDepth(t *testing.T) {
	p := &Policy{
		Version:       "1.0",
		DefaultAction: ActionDeny,
		Settings:      Settings{MaxSpawnDepth: -1},
		Servers:       []Server{{Name: "test", Allowed: true, Tools: []ToolRule{{Name: "test"}}}},
	}
	res := Lint(p)
	found := false
	for _, v := range res.Violations {
		if v.Severity == SeverityError && strings.Contains(v.Message, "max_spawn_depth must be non-negative") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected max_spawn_depth error, violations: %+v", res.Violations)
	}
}

func TestLoadDelegatesFlag(t *testing.T) {
	p, err := Load([]byte(`
version: "1.0"
default_action: deny
settings:
  max_spawn_depth: 2
servers:
  - name: "orchestrator"
    allowed: true
    tools:
      - name: "spawn_agent"
        allowed: true
        delegates: true
      - name: "file_read"
        allowed: true
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if p.Settings.MaxSpawnDepth != 2 {
		t.Fatalf("max_spawn_depth=%d want 2", p.Settings.MaxSpawnDepth)
	}
	var spawn, read *ToolRule
	for i := range p.Servers[0].Tools {
		switch p.Servers[0].Tools[i].Name {
		case "spawn_agent":
			spawn = &p.Servers[0].Tools[i]
		case "file_read":
			read = &p.Servers[0].Tools[i]
		}
	}
	if spawn == nil || !spawn.Delegates {
		t.Fatal("spawn_agent must parse delegates:true")
	}
	if read == nil || read.Delegates {
		t.Fatal("file_read must default delegates:false")
	}
}

func TestLoadMaxSpawnDepthDefaultsOff(t *testing.T) {
	p, err := Load([]byte(`
version: "1.0"
default_action: deny
servers:
  - name: "s"
    allowed: true
    tools:
      - name: "t"
        allowed: true
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if p.Settings.MaxSpawnDepth != 0 {
		t.Fatalf("max_spawn_depth=%d want 0 (unenforced default)", p.Settings.MaxSpawnDepth)
	}
}
