// Package compositiongraph implements Capability Composition Graph Proofs (H41).
package compositiongraph

const SchemaVersion = 1

const (
	EffectRead, EffectTransform, EffectSend                                   = "READ", "TRANSFORM", "SEND"
	GraphPresent, GraphAbsent, GraphInvalid, GraphDisabled                    = "PRESENT", "ABSENT", "INVALID", "DISABLED"
	ContinuityValid, ContinuityInvalid, ContinuityDisabled                    = "VALID", "INVALID", "DISABLED"
	AuthorityPresent, AuthorityAbsent, AuthorityInvalid, AuthorityDisabled    = "PRESENT", "ABSENT", "INVALID", "DISABLED"
	CompositionValid, CompositionInvalid, CompositionDisabled                 = "VALID", "INVALID", "DISABLED"
	ProofValid, ProofInvalid, ProofDisabled                                   = "VALID", "INVALID", "DISABLED"
	VerdictAllow, VerdictDeny                                                 = "ALLOW", "DENY"
	CanonicalMandateID, CanonicalDestination                                  = "mandate:report-export", "mcp:external"
	CredentialSource, CredentialArtifact, ContextArtifact, ExternalDisclosure = "CREDENTIAL_SOURCE", "CREDENTIAL_ARTIFACT", "CONTEXT_ARTIFACT", "EXTERNAL_DISCLOSURE"
	ReportSource, ReportArtifact, ReportContext, ExternalDelivery             = "REPORT_SOURCE", "REPORT_ARTIFACT", "REPORT_CONTEXT", "EXTERNAL_DELIVERY"
	SkillCredentialDiscovery, SkillContextNormalizer, SkillMCPSubmitter       = "skill:credential-discovery", "skill:context-normalizer", "skill:mcp-submitter"
	SkillReportReader, SkillReportTransformer, SkillReportSender              = "skill:report-reader", "skill:report-transformer", "skill:report-sender"
	EdgeDiscoverCredentials, EdgeNormalizeCredential, EdgeSubmitExternal      = "edge:discover-credentials", "edge:normalize-credential", "edge:submit-external"
	EdgeReadReport, EdgeTransformReport, EdgeSendReport                       = "edge:read-report", "edge:transform-report", "edge:send-report"
	CanonicalAttackActionID, LegitimateActionID                               = "action:credential-external-disclosure", "action:report-external-delivery"
	FixtureSampleSize, FixtureSeed                                            = 8, 41041
)

type CapabilityMandate struct {
	MandateID                                                   string
	AllowedEffects, AllowedDestinations, AllowedArtifactClasses []string
}
type CapabilityEdge struct {
	EdgeID, FromArtifactClass, ToArtifactClass, EffectClass, Destination string
}
type InstalledSkill struct {
	SkillID string
	Edges   []CapabilityEdge
}
type StepReference struct{ SkillID, EdgeID string }
type EvaluationRoot struct {
	SchemaVersion      int
	Mandate            CapabilityMandate
	InstalledSkills    []InstalledSkill
	CompositionEnabled bool
}
type ProposedAction struct {
	ActionID, StartArtifactClass, FinalArtifactClass, Destination                              string
	Steps                                                                                      []StepReference
	ClaimedSignaturesValid, ClaimedIndividualAllow, ClaimedCompositionValid, ClaimedAuthorized bool
}
type Decision struct {
	ActionID, MandateID, StartArtifactClass, FinalArtifactClass, Destination                                 string
	StepCount, SkillCount, EdgeCount                                                                         int
	Verdict, Proof, Reason                                                                                   string
	GraphStatus, PathContinuity, EffectAuthority, DestinationAuthority, ArtifactAuthority, CompositionStatus string
	Evidence                                                                                                 [8]string
}
