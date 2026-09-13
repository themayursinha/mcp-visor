package lineage

// AgentIdentity is a registered principal. Claims on the wire are never
// trusted; only this registry entry can satisfy R1.
type AgentIdentity struct {
	InstanceID       string `yaml:"instance_id" json:"instance_id"`
	ParentAgentID    string `yaml:"parent_agent_id,omitempty" json:"parent_agent_id,omitempty"`
	HumanPrincipalID string `yaml:"human_principal_id" json:"human_principal_id"`
	CreatedAt        string `yaml:"created_at" json:"created_at"`
	Expiry           string `yaml:"expiry" json:"expiry"`
}

// AuthorityGrant is a registered delegation. Root grants have an empty
// ParentGrantID and must be issued by a human principal.
type AuthorityGrant struct {
	GrantID        string   `yaml:"grant_id" json:"grant_id"`
	Issuer         string   `yaml:"issuer" json:"issuer"`
	SubjectAgentID string   `yaml:"subject_agent_id" json:"subject_agent_id"`
	ParentGrantID  string   `yaml:"parent_grant_id,omitempty" json:"parent_grant_id,omitempty"`
	Capabilities   []string `yaml:"capabilities" json:"capabilities"`
	ResourceScope  []string `yaml:"resource_scope" json:"resource_scope"`
	IssuedAt       string   `yaml:"issued_at" json:"issued_at"`
	Expiry         string   `yaml:"expiry" json:"expiry"`
}

// Trajectory pins a consequential action. Capability is singular and mandatory.
type Trajectory struct {
	TrajectoryID   string   `yaml:"trajectory_id" json:"trajectory_id"`
	ActorAgentID   string   `yaml:"actor_agent_id" json:"actor_agent_id"`
	GrantID        string   `yaml:"grant_id" json:"grant_id"`
	Capability     string   `yaml:"capability" json:"capability"`
	Server         string   `yaml:"server" json:"server"`
	Tool           string   `yaml:"tool" json:"tool"`
	ResourceScope  []string `yaml:"resource_scope" json:"resource_scope"`
	Effect         string   `yaml:"effect" json:"effect"`
	PriorStateHash string   `yaml:"prior_state_hash" json:"prior_state_hash"`
}

// Envelope is the untrusted lineage claim a caller presents on tools/call.
// ActorAgentID is the proxy ClientID, never a field inside `_lineage`.
type Envelope struct {
	ActorAgentID   string
	GrantID        string
	Capability     string
	Resource       string
	Effect         string
	PriorStateHash string
	TrajectoryID   string
	Server         string
	Tool           string
}

// Evidence is the additive audit payload for a lineage-gated decision.
type Evidence struct {
	ActorAgentID     string
	ParentAgentID    string
	HumanPrincipalID string
	GrantID          string
	GrantChain       []string
	Capability       string
	Resource         string
	Effect           string
	TrajectoryID     string
	PriorStateHash   string
	Rule             string
}

// Registry is the indexed, fail-closed view of identity + trajectories.
type Registry struct {
	agents       map[string]AgentIdentity
	grants       map[string]AuthorityGrant
	trajectories map[string]Trajectory
}

// Decision is the lineage allow/deny result. Reason is empty on allow.
type Decision struct {
	Allow  bool
	Reason string
}

const (
	ReasonUnregisteredPrincipal = "lineage:unregistered-principal"
	ReasonDelegationCeiling     = "lineage:delegation-ceiling-violation"
	ReasonTrajectoryMismatch    = "lineage:trajectory-mismatch"
)
