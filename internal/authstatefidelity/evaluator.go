package authstatefidelity

import (
	"errors"
	"sort"
	"strconv"
)

const (
	reasonInvalidRoot, reasonActionAbsent, reasonSubjectAbsent           = "invalid evaluation root", "action identifier absent", "subject identifier absent"
	reasonPermissionAbsent, reasonCitationAbsent, reasonDisabled         = "permission absent", "source grant citation absent", "authorization state disabled"
	reasonCitedAbsent, reasonNotGrant, reasonNotYet                      = "cited source event absent", "cited source event is not a grant", "cited grant not yet effective"
	reasonPairMismatch, reasonPrincipal, reasonRevoked, reasonAuthorized = "cited grant does not match requested pair", "grant principal not authorized", "cited grant revoked", "authorized"
)

func canGrant(root EvaluationRoot, principal, perm string) bool {
	for _, gp := range root.GrantPrincipals {
		if gp.PrincipalID == principal {
			for _, p := range gp.GrantablePermissions {
				if p == perm {
					return true
				}
			}
		}
	}
	return false
}

func structuralOK(r EvaluationRoot) bool {
	if r.SchemaVersion != SchemaVersion || r.CurrentTick < 0 || len(r.EventLog) == 0 || len(r.GrantPrincipals) == 0 {
		return false
	}
	eids, last := map[string]struct{}{}, -1
	for _, e := range r.EventLog {
		if e.EventID == "" || e.PrincipalID == "" || e.SubjectID == "" || e.Permission == "" || e.Tick < 0 || e.Tick < last {
			return false
		}
		if _, ok := eids[e.EventID]; ok {
			return false
		}
		eids[e.EventID], last = struct{}{}, e.Tick
		if (e.Kind != EventGrant || e.GrantEventID != "") && (e.Kind != EventRevoke || e.GrantEventID == "") {
			return false
		}
	}
	pids := map[string]struct{}{}
	for _, gp := range r.GrantPrincipals {
		if gp.PrincipalID == "" {
			return false
		}
		if _, ok := pids[gp.PrincipalID]; ok {
			return false
		}
		pids[gp.PrincipalID] = struct{}{}
		seen := map[string]struct{}{}
		for _, p := range gp.GrantablePermissions {
			if p == "" {
				return false
			}
			if _, ok := seen[p]; ok {
				return false
			}
			seen[p] = struct{}{}
		}
	}
	return true
}

func reduce(root EvaluationRoot) []AuthorizationBinding {
	active := map[string]AuthorizationBinding{}
	for _, e := range root.EventLog {
		if e.Tick > root.CurrentTick {
			continue
		}
		if e.Kind == EventGrant {
			if canGrant(root, e.PrincipalID, e.Permission) {
				active[e.EventID] = AuthorizationBinding{e.SubjectID, e.Permission, e.EventID, e.PrincipalID, e.Tick}
			}
			continue
		}
		g, ok := active[e.GrantEventID]
		if ok && g.PrincipalID == e.PrincipalID && g.SubjectID == e.SubjectID && g.Permission == e.Permission && canGrant(root, e.PrincipalID, e.Permission) {
			delete(active, e.GrantEventID)
		}
	}
	out := make([]AuthorizationBinding, 0, len(active))
	for _, b := range active {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SubjectID+"\x00"+out[i].Permission+"\x00"+out[i].SourceEventID+"\x00"+out[i].PrincipalID <
			out[j].SubjectID+"\x00"+out[j].Permission+"\x00"+out[j].SourceEventID+"\x00"+out[j].PrincipalID
	})
	return out
}

func RecomputeAuthorizationState(root EvaluationRoot) ([]AuthorizationBinding, error) {
	if !structuralOK(root) {
		return nil, errors.New(reasonInvalidRoot)
	}
	if !root.AuthorizationStateEnabled {
		return nil, errors.New(reasonDisabled)
	}
	return reduce(root), nil
}

func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{ActionID: action.ActionID, SubjectID: action.SubjectID, Permission: action.Permission, CitedGrantEventID: action.CitedGrantEventID,
		CurrentTick: root.CurrentTick, EventCount: len(root.EventLog), Verdict: VerdictDeny, Proof: ProofInvalid, Reason: reasonInvalidRoot,
		SourceEventStatus: SourceInvalid, PrincipalAuthority: PrincipalInvalid, ExactState: StateInvalid}
	var ev AuthorizationEvent
	found := false
	for _, e := range root.EventLog {
		if e.EventID == action.CitedGrantEventID {
			ev, found, d.SourcePrincipalID = e, true, e.PrincipalID
			break
		}
	}
	switch {
	case !structuralOK(root):
	case action.ActionID == "":
		d.Reason = reasonActionAbsent
	case action.SubjectID == "":
		d.Reason = reasonSubjectAbsent
	case action.Permission == "":
		d.Reason = reasonPermissionAbsent
	case action.CitedGrantEventID == "":
		d.Reason = reasonCitationAbsent
	case !root.AuthorizationStateEnabled:
		d.Proof, d.Reason, d.SourceEventStatus, d.PrincipalAuthority, d.ExactState = ProofDisabled, reasonDisabled, SourceDisabled, PrincipalDisabled, StateDisabled
	default:
		okP, on := found && ev.Kind == EventGrant && canGrant(root, ev.PrincipalID, ev.Permission), false
		for _, b := range reduce(root) {
			if b.SourceEventID == action.CitedGrantEventID && b.SubjectID == action.SubjectID && b.Permission == action.Permission {
				on = true
			}
		}
		if okP {
			d.PrincipalAuthority = PrincipalPresent
		} else if found && ev.Kind == EventGrant {
			d.PrincipalAuthority = PrincipalAbsent
		}
		pair := found && ev.SubjectID == action.SubjectID && ev.Permission == action.Permission
		switch {
		case !found:
			d.SourceEventStatus = SourceAbsent
		case ev.Kind != EventGrant || !pair || !okP:
			d.SourceEventStatus = SourceInvalid
		case ev.Tick > root.CurrentTick:
			d.SourceEventStatus = SourceNotYetEffective
		case !on:
			d.SourceEventStatus = SourceRevoked
		default:
			d.SourceEventStatus = SourceValid
		}
		d.ExactState = map[bool]string{true: StateAuthorized, false: StateUnauthorized}[on]
		steps := []struct {
			ok bool
			r  string
		}{{found, reasonCitedAbsent}, {ev.Kind == EventGrant, reasonNotGrant}, {ev.Tick <= root.CurrentTick, reasonNotYet}, {pair, reasonPairMismatch}, {okP, reasonPrincipal}, {on, reasonRevoked}}
		d.Verdict, d.Proof, d.Reason = VerdictAllow, ProofValid, reasonAuthorized
		for _, s := range steps {
			if !s.ok {
				d.Verdict, d.Proof, d.Reason = VerdictDeny, ProofInvalid, s.r
				break
			}
		}
	}
	mem := map[bool]string{true: "PRESENT", false: "ABSENT"}[action.ClaimedMemoryPermission]
	effect := map[bool]string{true: "ACTION ALLOWED", false: "ACTION DENIED"}[d.Verdict == VerdictAllow]
	d.Evidence = [8]string{"Authorization root tick=" + strconv.Itoa(d.CurrentTick) + " events=" + strconv.Itoa(d.EventCount),
		"Requested pair " + d.SubjectID + "|" + d.Permission, "Memory claim permission=" + mem + " grant=" + d.CitedGrantEventID,
		"Source event " + d.CitedGrantEventID + " principal=" + d.SourcePrincipalID + " status=" + d.SourceEventStatus,
		"Authority principal=" + d.PrincipalAuthority + " exact_state=" + d.ExactState,
		"Authorization-State Fidelity Proof " + d.Proof, "reason " + d.Reason, effect}
	return d
}
