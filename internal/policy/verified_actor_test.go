package policy_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/actorcontext"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func verifiedActorYAML() string {
	return `
version: "1.0"
default_action: deny
settings:
  require_verified_actor: true
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
        required_scopes: ["write"]
`
}

func sealedActor(t *testing.T, scopes []string, exp time.Time) *actorcontext.Context {
	t.Helper()
	c := &actorcontext.Context{
		Version:            actorcontext.VersionV1,
		PrincipalID:        "user1",
		ActingAgent:        "coding-agent",
		Transaction:        "txn-phase1",
		ActorChain:         []actorcontext.ActorRef{{ID: "user1"}, {ID: "planner"}, {ID: "coding-agent"}},
		Scopes:             scopes,
		Issuer:             "https://sts.example.test",
		Audience:           "https://visor-gateway.example.test",
		TokenID:            "jti-phase1",
		ExpiresAt:          exp,
		ProofKeyThumbprint: "thumb",
		VerificationMethod: actorcontext.VerificationSTSDpop,
	}
	if err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEvaluateRequiresVerifiedActor(t *testing.T) {
	p, err := policy.Load([]byte(verifiedActorYAML()))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(p)
	req := mcp.ToolsCallRequest{Name: "write_file", Arguments: json.RawMessage(`{"path":"/tmp/a"}`)}
	d := eng.Evaluate("filesystem", req)
	if d.Action != policy.ActionDeny || !strings.Contains(d.Reason, "verified actor context required") {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluateVerifiedActorWriteScope(t *testing.T) {
	p, err := policy.Load([]byte(verifiedActorYAML()))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(p)
	eng.SetVerifiedActor(sealedActor(t, []string{"read", "write"}, time.Now().UTC().Add(time.Hour)))
	req := mcp.ToolsCallRequest{Name: "write_file", Arguments: json.RawMessage(`{"path":"/tmp/a"}`)}
	d := eng.Evaluate("filesystem", req)
	if d.Action != policy.ActionAllow {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluateReadScopeCannotWrite(t *testing.T) {
	p, err := policy.Load([]byte(verifiedActorYAML()))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(p)
	eng.SetVerifiedActor(sealedActor(t, []string{"read"}, time.Now().UTC().Add(time.Hour)))
	req := mcp.ToolsCallRequest{Name: "write_file", Arguments: json.RawMessage(`{"path":"/tmp/a"}`)}
	d := eng.Evaluate("filesystem", req)
	if d.Action != policy.ActionDeny || !strings.Contains(d.Reason, "verified actor scope missing: write") {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluateExpiredVerifiedActor(t *testing.T) {
	p, err := policy.Load([]byte(verifiedActorYAML()))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(p)
	eng.SetVerifiedActor(sealedActor(t, []string{"write"}, time.Now().UTC().Add(-time.Minute)))
	req := mcp.ToolsCallRequest{Name: "write_file", Arguments: json.RawMessage(`{"path":"/tmp/a"}`)}
	d := eng.Evaluate("filesystem", req)
	if d.Action != policy.ActionDeny || !strings.Contains(d.Reason, "expired") {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluateVerifiedActorOffAllowsWithoutContext(t *testing.T) {
	p, err := policy.Load([]byte(`
version: "1.0"
default_action: deny
servers:
  - name: "filesystem"
    allowed: true
    tools:
      - name: "write_file"
        allowed: true
        risk: high
`))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(p)
	req := mcp.ToolsCallRequest{Name: "write_file", Arguments: json.RawMessage(`{}`)}
	d := eng.Evaluate("filesystem", req)
	if d.Action != policy.ActionAllow {
		t.Fatalf("negative control: %+v", d)
	}
}
