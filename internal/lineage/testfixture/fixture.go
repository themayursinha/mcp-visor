package testfixture

import (
	"fmt"

	"github.com/themayursinha/mcp-visor/internal/lineage"
)

const (
	Created      = "2026-01-01T00:00:00Z"
	Expiry       = "2099-12-31T00:00:00Z"
	Human        = "mayur"
	Planner      = "planner-agent-1"
	Coding       = "coding-agent-1"
	GrantPlanner = "grant-planner-1"
	GrantCoding  = "grant-coding-1"
	CapWrite     = "github.repo.write"
	CapRead      = "github.repo.read"
	Resource     = "repo:themayursinha/mcp-visor"
	Server       = "github"
	Tool         = "write_file"
	Effect       = "write"
	Traj         = "traj-write-1"
	Prior        = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	Now          = "2026-06-15T00:00:00Z"
)

func Agents() []lineage.AgentIdentity {
	return []lineage.AgentIdentity{
		{InstanceID: Planner, HumanPrincipalID: Human, CreatedAt: Created, Expiry: Expiry},
		{InstanceID: Coding, ParentAgentID: Planner, HumanPrincipalID: Human, CreatedAt: Created, Expiry: Expiry},
	}
}

func Grants() []lineage.AuthorityGrant {
	return []lineage.AuthorityGrant{
		{GrantID: GrantPlanner, Issuer: Human, SubjectAgentID: Planner, Capabilities: []string{CapWrite}, ResourceScope: []string{Resource}, IssuedAt: Created, Expiry: Expiry},
		{GrantID: GrantCoding, Issuer: Planner, SubjectAgentID: Coding, ParentGrantID: GrantPlanner, Capabilities: []string{CapWrite}, ResourceScope: []string{Resource}, IssuedAt: Created, Expiry: Expiry},
	}
}

func Trajectories() []lineage.Trajectory {
	return []lineage.Trajectory{
		{TrajectoryID: Traj, ActorAgentID: Coding, GrantID: GrantCoding, Capability: CapWrite, Server: Server, Tool: Tool, ResourceScope: []string{Resource}, Effect: Effect, PriorStateHash: Prior},
	}
}

func Envelope() lineage.Envelope {
	return lineage.Envelope{
		ActorAgentID: Coding, GrantID: GrantCoding, Capability: CapWrite, Resource: Resource,
		Effect: Effect, PriorStateHash: Prior, TrajectoryID: Traj, Server: Server, Tool: Tool,
	}
}

func Args() map[string]any {
	return map[string]any{
		"path": "README.md", "content": "ok",
		"_lineage": map[string]any{
			"grant_id": GrantCoding, "capability": CapWrite, "resource": Resource,
			"effect": Effect, "prior_state_hash": Prior, "trajectory_id": Traj,
		},
	}
}

// PolicyYAML is the canonical gated github/write_file policy. Callers append
// extra YAML (approval, redaction) rather than repeating the identity graph.
func PolicyYAML() string {
	return fmt.Sprintf(`version: "1.0"
default_action: deny
identity:
  version: 1
  agents:
    - {instance_id: %s, human_principal_id: %s, created_at: %q, expiry: %q}
    - {instance_id: %s, parent_agent_id: %s, human_principal_id: %s, created_at: %q, expiry: %q}
  grants:
    - {grant_id: %s, issuer: %s, subject_agent_id: %s, capabilities: [%q], resource_scope: [%q], issued_at: %q, expiry: %q}
    - {grant_id: %s, issuer: %s, subject_agent_id: %s, parent_grant_id: %s, capabilities: [%q], resource_scope: [%q], issued_at: %q, expiry: %q}
trajectories:
  - {trajectory_id: %s, actor_agent_id: %s, grant_id: %s, capability: %s, server: %s, tool: %s, resource_scope: [%q], effect: %s, prior_state_hash: %s}
servers:
  - name: %s
    allowed: true
    tools:
      - name: %s
        allowed: true
        risk: high
        rules: [{type: lineage_require}]
`, Planner, Human, Created, Expiry, Coding, Planner, Human, Created, Expiry,
		GrantPlanner, Human, Planner, CapWrite, Resource, Created, Expiry,
		GrantCoding, Planner, Coding, GrantPlanner, CapWrite, Resource, Created, Expiry,
		Traj, Coding, GrantCoding, CapWrite, Server, Tool, Resource, Effect, Prior,
		Server, Tool)
}

// MarkerPolicyYAML embeds marker in actor-adjacent lineage fields and a
// grant-chain element so snapshot-redaction tests can prove non-leakage.
func MarkerPolicyYAML(marker string, redact, approval bool) string {
	gPlanner := GrantPlanner + "-" + marker
	gCoding := GrantCoding + "-" + marker
	traj := Traj + "-" + marker
	human := Human + "-" + marker
	y := fmt.Sprintf(`version: "1.0"
default_action: deny
identity:
  version: 1
  agents:
    - {instance_id: %s, human_principal_id: %s, created_at: %q, expiry: %q}
    - {instance_id: %s, parent_agent_id: %s, human_principal_id: %s, created_at: %q, expiry: %q}
  grants:
    - {grant_id: %s, issuer: %s, subject_agent_id: %s, capabilities: [%q], resource_scope: [%q], issued_at: %q, expiry: %q}
    - {grant_id: %s, issuer: %s, subject_agent_id: %s, parent_grant_id: %s, capabilities: [%q], resource_scope: [%q], issued_at: %q, expiry: %q}
trajectories:
  - {trajectory_id: %s, actor_agent_id: %s, grant_id: %s, capability: %s, server: %s, tool: %s, resource_scope: [%q], effect: %s, prior_state_hash: %s}
servers:
  - name: %s
    allowed: true
    tools:
      - name: %s
        allowed: true
        risk: high
        approval_required: %t
        rules: [{type: lineage_require}]
`, Planner, human, Created, Expiry, Coding, Planner, human, Created, Expiry,
		gPlanner, human, Planner, CapWrite, Resource, Created, Expiry,
		gCoding, Planner, Coding, gPlanner, CapWrite, Resource, Created, Expiry,
		traj, Coding, gCoding, CapWrite, Server, Tool, Resource, Effect, Prior,
		Server, Tool, approval)
	if redact {
		y += fmt.Sprintf("redaction:\n  patterns:\n    - {name: linraw, regex: %q, replacement: \"[REDACTED]\"}\n", marker)
	}
	return y
}

func MarkerArgs(marker string) map[string]any {
	return map[string]any{
		"path": "README.md", "content": "ok",
		"_lineage": map[string]any{
			"grant_id": GrantCoding + "-" + marker, "capability": CapWrite, "resource": Resource,
			"effect": Effect, "prior_state_hash": Prior, "trajectory_id": Traj + "-" + marker,
		},
	}
}
