// Package toolcorrelation implements Cross-Tool Correlation Proofs (H42).
package toolcorrelation

const SchemaVersion = 1

const (
	GraphPresent, GraphAbsent, GraphInvalid, GraphDisabled                     = "PRESENT", "ABSENT", "INVALID", "DISABLED"
	TrajectoryValid, TrajectoryInvalid, TrajectoryDisabled                     = "VALID", "INVALID", "DISABLED"
	CapabilityPresent, CapabilityAbsent, CapabilityInvalid, CapabilityDisabled = "PRESENT", "ABSENT", "INVALID", "DISABLED"
	CeilingPresent, CeilingAbsent, CeilingInvalid, CeilingDisabled             = "PRESENT", "ABSENT", "INVALID", "DISABLED"
	UsageWithin, UsageExceeded, UsageInvalid, UsageDisabled                    = "WITHIN", "EXCEEDED", "INVALID", "DISABLED"
	CorrelationValid, CorrelationInvalid, CorrelationDisabled                  = "VALID", "INVALID", "DISABLED"
	ProofValid, ProofInvalid, ProofDisabled                                    = "VALID", "INVALID", "DISABLED"
	VerdictAllow, VerdictDeny                                                  = "ALLOW", "DENY"
	CanonicalCapabilityID                                                      = "capability:repository-read"
	CanonicalCeilingUnits                                                      = 3
	GitHubServerID, DriveServerID, NotionServerID                              = "mcp:github", "mcp:drive", "mcp:notion"
	GitHubSearchTool, DriveSearchTool, NotionSearchTool, GitHubReadTool        = "search_code", "search", "search", "get_file_contents"
	GitHubSearchUseID, DriveSearchUseID, NotionSearchUseID, GitHubReadUseID    = "use:github-search-1", "use:drive-search-1", "use:notion-search-1", "use:github-read-1"
	CanonicalAttackActionID, LegitimateActionID                                = "action:cross-server-repository-sweep", "action:bounded-repository-research"
	FixtureSampleSize, FixtureSeed                                             = 8, 42042
)

type CapabilityCeiling struct {
	CapabilityID string
	MaxUnits     int
}
type ResourceUse struct {
	UseID, ServerID, ToolName, CapabilityID string
	Units                                   int
}
type CorrelationEdge struct{ FromUseID, ToUseID string }
type UseReference struct{ UseID, ServerID, ToolName string }
type EvaluationRoot struct {
	SchemaVersion      int
	CapabilityCeilings []CapabilityCeiling
	ResourceUses       []ResourceUse
	CorrelationEdges   []CorrelationEdge
	CorrelationEnabled bool
}
type ProposedAction struct {
	ActionID, CapabilityID                                           string
	Uses                                                             []UseReference
	ClaimedPerToolAllow, ClaimedServerHopInnocent, ClaimedAuthorized bool
	ClaimedRemainingQuota                                            int
}
type Decision struct {
	ActionID, CapabilityID                                                                         string
	UseCount, ServerCount, ToolCount, TotalUnits, CeilingUnits                                     int
	Verdict, Proof, Reason                                                                         string
	GraphStatus, TrajectoryStatus, CapabilityStatus, CeilingStatus, UsageStatus, CorrelationStatus string
	Evidence                                                                                       [8]string
}
