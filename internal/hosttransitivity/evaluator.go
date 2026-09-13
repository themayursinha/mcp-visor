package hosttransitivity

const (
	reasonInvalidRoot  = "invalid evaluation root"
	reasonActionAbsent = "action identifier absent"
	reasonUnsupported  = "unsupported effect class"
	reasonReqPrincipal = "requested principal absent"
	reasonReqHost      = "requested host absent"
	reasonReqDomain    = "requested execution domain absent"
	reasonObsPrincipal = "observed principal absent"
	reasonObsHost      = "observed host absent"
	reasonObsDomain    = "observed execution domain absent"
	reasonTargetAbsent = "target host absent"
	reasonDisabled     = "host authority disabled"
	reasonHeldBinding  = "requested binding does not match held grant binding"
	reasonObsBinding   = "observed binding does not match requested binding"
	reasonCredRead     = "credential read outside grant"
	reasonRemoteExec   = "remote-exec target host undeclared"
	reasonBulkEgress   = "bulk egress outside declared paths"
	reasonPkgInstall   = "package install not granted on bound host"
	reasonListener     = "persistent listener not granted"
	reasonReplica      = "replica bootstrap lacks fresh local grant"
	reasonTransfer     = "transfer host undeclared"
	reasonAuthorized   = "authorized"
)

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func uniqueFilled(xs []string) bool {
	seen := map[string]struct{}{}
	for _, x := range xs {
		if x == "" {
			return false
		}
		if _, dup := seen[x]; dup {
			return false
		}
		seen[x] = struct{}{}
	}
	return true
}
func pick(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
func knownEffect(e string) bool {
	return e == EffectTransfer || e == EffectCredentialRead || e == EffectRemoteExec || e == EffectBulkEgress ||
		e == EffectPackageInstall || e == EffectPersistentListener || e == EffectReplicaBootstrap
}
func structuralOK(r EvaluationRoot) bool {
	g := r.Grant
	return r.SchemaVersion == SchemaVersion && r.HeldPrincipalID != "" && r.HeldHostID != "" && r.HeldExecutionDomain != "" &&
		g.GrantID != "" && g.PrincipalID == r.HeldPrincipalID && g.BoundHostID == r.HeldHostID && g.BoundExecutionDomain == r.HeldExecutionDomain &&
		len(g.DeclaredHosts) > 0 && uniqueFilled(g.DeclaredHosts) && has(g.DeclaredHosts, g.BoundHostID) &&
		uniqueFilled(append([]string{}, g.CredentialReadPaths...)) && uniqueFilled(append([]string{}, g.BulkEgressPaths...))
}
func hostComp(e, target string, g HostGrant, held string) bool {
	switch e {
	case EffectCredentialRead, EffectPackageInstall, EffectPersistentListener, EffectReplicaBootstrap:
		return target == g.BoundHostID
	case EffectRemoteExec, EffectBulkEgress:
		return has(g.DeclaredHosts, target)
	case EffectTransfer:
		return has(g.DeclaredHosts, held) && has(g.DeclaredHosts, target)
	}
	return false
}

func EvaluateHostTransitivity(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{
		ActionID: action.ActionID, EffectClass: action.EffectClass, GrantID: root.Grant.GrantID,
		HeldPrincipalID: root.HeldPrincipalID, HeldHostID: root.HeldHostID, HeldExecutionDomain: root.HeldExecutionDomain,
		RequestedPrincipalID: action.RequestedPrincipalID, RequestedHostID: action.RequestedHostID, RequestedExecutionDomain: action.RequestedExecutionDomain,
		ObservedPrincipalID: action.ObservedPrincipalID, ObservedHostID: action.ObservedHostID, ObservedExecutionDomain: action.ObservedExecutionDomain,
		TargetHostID: action.TargetHostID, Verdict: VerdictDeny, Proof: ProofInvalid, Reason: reasonInvalidRoot,
		LocalGrantBinding: BindingInvalid, TargetHostAuthority: AuthorityInvalid, PathAuthority: PathInvalid, EdgeAuthority: AuthorityInvalid,
	}
	early := []struct {
		ok bool
		r  string
	}{
		{structuralOK(root), reasonInvalidRoot}, {action.ActionID != "", reasonActionAbsent}, {knownEffect(action.EffectClass), reasonUnsupported},
		{action.RequestedPrincipalID != "", reasonReqPrincipal}, {action.RequestedHostID != "", reasonReqHost},
		{action.RequestedExecutionDomain != "", reasonReqDomain}, {action.ObservedPrincipalID != "", reasonObsPrincipal},
		{action.ObservedHostID != "", reasonObsHost}, {action.ObservedExecutionDomain != "", reasonObsDomain}, {action.TargetHostID != "", reasonTargetAbsent},
	}
	for i, s := range early {
		if !s.ok {
			if i > 0 {
				d.Reason = s.r
			}
			d.Evidence = evidence(d)
			return d
		}
	}
	if !root.HostAuthorityEnabled {
		d.Verdict, d.Proof, d.Reason = VerdictDeny, ProofDisabled, reasonDisabled
		d.LocalGrantBinding, d.TargetHostAuthority, d.PathAuthority, d.EdgeAuthority = BindingDisabled, AuthorityDisabled, PathDisabled, AuthorityDisabled
		d.Evidence = evidence(d)
		return d
	}
	g := root.Grant
	c11 := action.RequestedPrincipalID == root.HeldPrincipalID && action.RequestedHostID == root.HeldHostID && action.RequestedExecutionDomain == root.HeldExecutionDomain
	c12 := action.ObservedPrincipalID == action.RequestedPrincipalID && action.ObservedHostID == action.RequestedHostID && action.ObservedExecutionDomain == action.RequestedExecutionDomain
	c13 := action.EffectClass != EffectCredentialRead || (action.TargetHostID == g.BoundHostID && has(g.CredentialReadPaths, action.ResourcePath))
	c14 := action.EffectClass != EffectRemoteExec || has(g.DeclaredHosts, action.TargetHostID)
	c15 := action.EffectClass != EffectBulkEgress || (has(g.DeclaredHosts, action.TargetHostID) && has(g.BulkEgressPaths, action.EgressPath))
	c16 := action.EffectClass != EffectPackageInstall || (action.TargetHostID == g.BoundHostID && g.AllowPackageInstall)
	c17 := action.EffectClass != EffectPersistentListener || (action.TargetHostID == g.BoundHostID && g.AllowPersistentListener)
	c18 := action.EffectClass != EffectReplicaBootstrap || (action.TargetHostID == g.BoundHostID && g.AllowReplicaBootstrap)
	c19 := action.EffectClass != EffectTransfer || (has(g.DeclaredHosts, root.HeldHostID) && has(g.DeclaredHosts, action.TargetHostID))
	d.LocalGrantBinding = pick(c11 && c12, BindingValid, BindingInvalid)
	d.TargetHostAuthority = pick(hostComp(action.EffectClass, action.TargetHostID, g, root.HeldHostID), AuthorityPresent, AuthorityAbsent)
	d.PathAuthority = PathNotApplicable
	if action.EffectClass == EffectCredentialRead {
		d.PathAuthority = pick(has(g.CredentialReadPaths, action.ResourcePath), PathPresent, PathAbsent)
	}
	if action.EffectClass == EffectBulkEgress {
		d.PathAuthority = pick(has(g.BulkEgressPaths, action.EgressPath), PathPresent, PathAbsent)
	}
	d.EdgeAuthority = pick(c13 && c14 && c15 && c16 && c17 && c18 && c19, AuthorityPresent, AuthorityAbsent)
	later := []struct {
		ok bool
		r  string
	}{{c11, reasonHeldBinding}, {c12, reasonObsBinding}, {c13, reasonCredRead}, {c14, reasonRemoteExec}, {c15, reasonBulkEgress}, {c16, reasonPkgInstall}, {c17, reasonListener}, {c18, reasonReplica}, {c19, reasonTransfer}}
	d.Verdict, d.Proof, d.Reason = VerdictAllow, ProofValid, reasonAuthorized
	for _, s := range later {
		if !s.ok {
			d.Verdict, d.Proof, d.Reason = VerdictDeny, ProofInvalid, s.r
			break
		}
	}
	d.Evidence = evidence(d)
	return d
}

func evidence(d Decision) [8]string {
	effect := "HOST EFFECT DENIED"
	if d.Verdict == VerdictAllow {
		effect = "HOST EFFECT ALLOWED"
	}
	return [8]string{
		"Grant " + d.GrantID, "Held binding " + d.HeldPrincipalID + "@" + d.HeldHostID + "/" + d.HeldExecutionDomain,
		"Requested binding " + d.RequestedPrincipalID + "@" + d.RequestedHostID + "/" + d.RequestedExecutionDomain,
		"Observed binding " + d.ObservedPrincipalID + "@" + d.ObservedHostID + "/" + d.ObservedExecutionDomain,
		"Target host " + d.TargetHostID,
		"Authority local=" + d.LocalGrantBinding + " target=" + d.TargetHostAuthority + " path=" + d.PathAuthority + " edge=" + d.EdgeAuthority,
		"Host Transitivity Proof " + d.Proof, effect,
	}
}

func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	return EvaluateHostTransitivity(root, action)
}
