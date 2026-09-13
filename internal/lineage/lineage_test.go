package lineage_test

import (
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/lineage"
	"github.com/themayursinha/mcp-visor/internal/lineage/testfixture"
)

func mustReg(t *testing.T, agents []lineage.AgentIdentity, grants []lineage.AuthorityGrant, trajs []lineage.Trajectory) *lineage.Registry {
	t.Helper()
	r, err := lineage.NewRegistry(agents, grants, trajs)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return r
}

func parseNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, testfixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func TestLineageRejectsAgentSelfParent(t *testing.T) {
	agents := testfixture.Agents()
	agents[1].ParentAgentID = agents[1].InstanceID
	if _, err := lineage.NewRegistry(agents, testfixture.Grants(), nil); err == nil {
		t.Fatal("agent self-parent must fail registry construction")
	}
}

func TestLineageRejectsAgentCycle(t *testing.T) {
	agents := testfixture.Agents()
	agents[0].ParentAgentID = agents[1].InstanceID
	if _, err := lineage.NewRegistry(agents, testfixture.Grants(), nil); err == nil {
		t.Fatal("multi-node agent cycle must fail registry construction")
	}
}

func TestLineageRejectsInvertedAgentInterval(t *testing.T) {
	agents := testfixture.Agents()
	agents[0].CreatedAt = testfixture.Expiry
	agents[0].Expiry = testfixture.Created
	if _, err := lineage.NewRegistry(agents, testfixture.Grants(), nil); err == nil {
		t.Fatal("created_at >= expiry must fail registry construction")
	}
}

func TestLineageRejectsInvertedGrantInterval(t *testing.T) {
	grants := testfixture.Grants()
	grants[0].IssuedAt = testfixture.Expiry
	grants[0].Expiry = testfixture.Created
	if _, err := lineage.NewRegistry(testfixture.Agents(), grants, nil); err == nil {
		t.Fatal("issued_at >= expiry must fail registry construction")
	}
}

func TestLineageRejectsFutureIdentity(t *testing.T) {
	agents := testfixture.Agents()
	agents[1].CreatedAt = "2099-01-01T00:00:00Z"
	reg, err := lineage.NewRegistry(agents, testfixture.Grants(), testfixture.Trajectories())
	if err != nil {
		t.Fatalf("future-created identity must load: %v", err)
	}
	d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, parseNow(t))
	if d.Allow || d.Reason != lineage.ReasonUnregisteredPrincipal {
		t.Fatalf("future identity must deny unregistered-principal, got allow=%v reason=%q", d.Allow, d.Reason)
	}
}

func TestLineageRejectsFutureGrant(t *testing.T) {
	grants := testfixture.Grants()
	grants[1].IssuedAt = "2099-01-01T00:00:00Z"
	reg, err := lineage.NewRegistry(testfixture.Agents(), grants, testfixture.Trajectories())
	if err != nil {
		t.Fatalf("future-issued grant must load: %v", err)
	}
	d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, parseNow(t))
	if d.Allow || d.Reason != lineage.ReasonDelegationCeiling {
		t.Fatalf("future grant must deny ceiling, got allow=%v reason=%q", d.Allow, d.Reason)
	}
}

func TestLineageReadCapabilityCannotAuthorizeWrite(t *testing.T) {
	reg := mustReg(t, testfixture.Agents(), testfixture.Grants(), testfixture.Trajectories())
	env := testfixture.Envelope()
	env.Capability = testfixture.CapRead
	d, _ := lineage.ValidateAt(env, reg, parseNow(t))
	if d.Allow {
		t.Fatal("github.repo.read must not authorize the trusted write_file/write trajectory")
	}
	if d.Reason != lineage.ReasonDelegationCeiling && d.Reason != lineage.ReasonTrajectoryMismatch {
		t.Fatalf("read-for-write must deny ceiling or mismatch, got %q", d.Reason)
	}
}

func TestLineageMissingTrajectoryDenied(t *testing.T) {
	reg := mustReg(t, testfixture.Agents(), testfixture.Grants(), testfixture.Trajectories())
	env := testfixture.Envelope()
	env.TrajectoryID = ""
	d, _ := lineage.ValidateAt(env, reg, parseNow(t))
	if d.Allow || d.Reason != lineage.ReasonTrajectoryMismatch {
		t.Fatalf("missing trajectory_id must deny mismatch, got allow=%v reason=%q", d.Allow, d.Reason)
	}
}

func TestLineageValidateTable(t *testing.T) {
	now := parseNow(t)
	reg := mustReg(t, testfixture.Agents(), testfixture.Grants(), testfixture.Trajectories())
	cases := []struct {
		name   string
		mut    func(*lineage.Envelope)
		reason string
	}{
		{"unknown actor", func(e *lineage.Envelope) { e.ActorAgentID = "orphan-1" }, lineage.ReasonUnregisteredPrincipal},
		{"default actor", func(e *lineage.Envelope) { e.ActorAgentID = "mcp-client" }, lineage.ReasonUnregisteredPrincipal},
		{"unknown grant", func(e *lineage.Envelope) { e.GrantID = "grant-forged" }, lineage.ReasonDelegationCeiling},
		{"wrong subject", func(e *lineage.Envelope) { e.ActorAgentID = testfixture.Planner }, lineage.ReasonDelegationCeiling},
		{"missing capability", func(e *lineage.Envelope) { e.Capability = "" }, lineage.ReasonDelegationCeiling},
		{"unknown traj", func(e *lineage.Envelope) { e.TrajectoryID = "traj-unknown" }, lineage.ReasonTrajectoryMismatch},
		{"effect mismatch", func(e *lineage.Envelope) { e.Effect = "delete" }, lineage.ReasonTrajectoryMismatch},
		{"prior mismatch", func(e *lineage.Envelope) { e.PriorStateHash = "sha256:deadbeef" }, lineage.ReasonTrajectoryMismatch},
		{"resource mismatch", func(e *lineage.Envelope) { e.Resource = "repo:other/x" }, lineage.ReasonDelegationCeiling},
		{"server mismatch", func(e *lineage.Envelope) { e.Server = "gitlab" }, lineage.ReasonTrajectoryMismatch},
		{"tool mismatch", func(e *lineage.Envelope) { e.Tool = "read_file" }, lineage.ReasonTrajectoryMismatch},
		{"absent grant", func(e *lineage.Envelope) { e.GrantID = "" }, lineage.ReasonDelegationCeiling},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := testfixture.Envelope()
			tc.mut(&env)
			d, _ := lineage.ValidateAt(env, reg, now)
			if d.Allow || d.Reason != tc.reason {
				t.Fatalf("got allow=%v reason=%q want %q", d.Allow, d.Reason, tc.reason)
			}
		})
	}
}

func TestLineageValidAllows(t *testing.T) {
	d, ev := lineage.ValidateAt(testfixture.Envelope(), mustReg(t, testfixture.Agents(), testfixture.Grants(), testfixture.Trajectories()), parseNow(t))
	if !d.Allow {
		t.Fatalf("canonical fixture must allow: %s", d.Reason)
	}
	if ev.HumanPrincipalID != testfixture.Human || ev.GrantID != testfixture.GrantCoding {
		t.Fatalf("allow evidence: %+v", ev)
	}
	if strings.Join(ev.GrantChain, ",") != testfixture.GrantPlanner+","+testfixture.GrantCoding {
		t.Fatalf("chain %v", ev.GrantChain)
	}
}

func TestLineageIntervalBoundaries(t *testing.T) {
	reg := mustReg(t, testfixture.Agents(), testfixture.Grants(), testfixture.Trajectories())
	start, _ := time.Parse(time.RFC3339, testfixture.Created)
	exp, _ := time.Parse(time.RFC3339, testfixture.Expiry)
	if d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, start); !d.Allow {
		t.Fatalf("now==start must allow, got %s", d.Reason)
	}
	if d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, exp); d.Allow || d.Reason != lineage.ReasonUnregisteredPrincipal {
		t.Fatalf("now==expiry must deny R1, got allow=%v %q", d.Allow, d.Reason)
	}
}

func TestLineageRejectsGrantCycle(t *testing.T) {
	g := testfixture.Grants()
	g[0].ParentGrantID = testfixture.GrantCoding
	if _, err := lineage.NewRegistry(testfixture.Agents(), g, nil); err == nil {
		t.Fatal("grant cycle must fail")
	}
	g = testfixture.Grants()
	g[1].ParentGrantID = testfixture.GrantCoding
	if _, err := lineage.NewRegistry(testfixture.Agents(), g, nil); err == nil {
		t.Fatal("grant self-parent must fail")
	}
}

func TestLineageEnvelopeIgnoresActorClaim(t *testing.T) {
	env := lineage.EnvelopeFromArgs("coding-agent-1", "github", "write_file", map[string]any{
		"_lineage": map[string]any{"actor": "forged", "grant_id": "g", "capability": "c"},
	})
	if env.ActorAgentID != "coding-agent-1" {
		t.Fatalf("actor must be proxy client, got %q", env.ActorAgentID)
	}
}

func TestLineageExpiredActorAndGrant(t *testing.T) {
	now := parseNow(t)
	agents := testfixture.Agents()
	agents[1].Expiry = "2026-02-01T00:00:00Z"
	reg, err := lineage.NewRegistry(agents, testfixture.Grants(), testfixture.Trajectories())
	if err != nil {
		t.Fatalf("expired identity must load: %v", err)
	}
	if d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, now); d.Allow || d.Reason != lineage.ReasonUnregisteredPrincipal {
		t.Fatalf("expired actor must deny R1, got allow=%v %q", d.Allow, d.Reason)
	}
	grants := testfixture.Grants()
	grants[1].Expiry = "2026-02-01T00:00:00Z"
	reg, err = lineage.NewRegistry(testfixture.Agents(), grants, testfixture.Trajectories())
	if err != nil {
		t.Fatalf("expired grant must load: %v", err)
	}
	if d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, now); d.Allow || d.Reason != lineage.ReasonDelegationCeiling {
		t.Fatalf("expired grant must deny R2, got allow=%v %q", d.Allow, d.Reason)
	}
}

func TestLineageEscalatedAndWrongIssuer(t *testing.T) {
	g := testfixture.Grants()
	g[1].Issuer = testfixture.Human
	if _, err := lineage.NewRegistry(testfixture.Agents(), g, nil); err == nil {
		t.Fatal("wrong-issuer child grant must fail load")
	}
	g = testfixture.Grants()
	g[1].Capabilities = []string{testfixture.CapWrite, "github.repo.admin"}
	reg, err := lineage.NewRegistry(testfixture.Agents(), g, testfixture.Trajectories())
	if err != nil {
		t.Fatalf("escalated child must load if trajectory covered: %v", err)
	}
	if d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, parseNow(t)); d.Allow || d.Reason != lineage.ReasonDelegationCeiling {
		t.Fatalf("escalated child must deny R2, got allow=%v %q", d.Allow, d.Reason)
	}
	g = testfixture.Grants()
	g[1].ResourceScope = []string{testfixture.Resource, "repo:other/x"}
	reg, err = lineage.NewRegistry(testfixture.Agents(), g, testfixture.Trajectories())
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := lineage.ValidateAt(testfixture.Envelope(), reg, parseNow(t)); d.Allow || d.Reason != lineage.ReasonDelegationCeiling {
		t.Fatalf("escalated resource must deny R2, got allow=%v %q", d.Allow, d.Reason)
	}
	g = testfixture.Grants()
	g[0].Capabilities = []string{testfixture.CapWrite, testfixture.CapRead}
	g[1].Capabilities = []string{testfixture.CapWrite, testfixture.CapRead}
	reg, err = lineage.NewRegistry(testfixture.Agents(), g, testfixture.Trajectories())
	if err != nil {
		t.Fatal(err)
	}
	env := testfixture.Envelope()
	env.Capability = testfixture.CapRead
	if d, _ := lineage.ValidateAt(env, reg, parseNow(t)); d.Allow || d.Reason != lineage.ReasonTrajectoryMismatch {
		t.Fatalf("grant-covered read vs write trajectory must mismatch, got allow=%v %q", d.Allow, d.Reason)
	}
}
