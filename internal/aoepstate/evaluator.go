package aoepstate

import (
	"strconv"
	"strings"
)

type evidenceFacts struct {
	schemaVersion      int
	enforcementEnabled bool
	taintPresent       bool
	completedPresent   bool
	operationEqual     bool
	requestEqual       bool
	resolvedFragments  int
	fragmentIDs        []string
}

func uniqueIDs(xs []string) bool {
	seen := map[string]struct{}{}
	for _, x := range xs {
		if x == "" {
			return false
		}
		if _, ok := seen[x]; ok {
			return false
		}
		seen[x] = struct{}{}
	}
	return true
}

func rootOK(r EvaluationRoot) bool {
	if r.SchemaVersion != SchemaVersion || r.CurrentPermissionEpoch <= 0 {
		return false
	}
	if !uniqueIDs(r.Taints) {
		return false
	}
	keys := map[string]struct{}{}
	for _, rec := range r.Completed {
		if rec.Key == "" || rec.Operation == "" || rec.RequestDigest == "" || rec.ResultDigest == "" {
			return false
		}
		if _, ok := keys[rec.Key]; ok {
			return false
		}
		keys[rec.Key] = struct{}{}
	}
	ids := map[string]struct{}{}
	for _, frag := range r.Fragments {
		if frag.FragmentID == "" || (frag.Authority != AuthorityDataOnly && frag.Authority != AuthorityUser) {
			return false
		}
		if _, ok := ids[frag.FragmentID]; ok {
			return false
		}
		ids[frag.FragmentID] = struct{}{}
	}
	return true
}

func taintKindExtras(a ProposedAction) bool {
	return a.PermissionEpoch != 0 || a.Operation != "" || a.RequestDigest != "" || a.IdempotencyKey != "" || a.RequiredAuthority != "" || len(a.FragmentIDs) != 0
}

func privilegedExtras(a ProposedAction) bool {
	return a.TaintID != "" || a.Operation != "" || a.RequestDigest != "" || a.IdempotencyKey != "" || a.RequiredAuthority != "" || len(a.FragmentIDs) != 0
}

func sideEffectExtras(a ProposedAction) bool {
	return a.TaintID != "" || a.PermissionEpoch != 0 || a.RequiredAuthority != "" || len(a.FragmentIDs) != 0
}

func sinkExtras(a ProposedAction) bool {
	return a.TaintID != "" || a.PermissionEpoch != 0 || a.Operation != "" || a.RequestDigest != "" || a.IdempotencyKey != ""
}

func hasTaint(root EvaluationRoot, id string) bool {
	for _, t := range root.Taints {
		if t == id {
			return true
		}
	}
	return false
}

func findCompleted(root EvaluationRoot, key string) (CompletedRecord, bool) {
	if key == "" {
		return CompletedRecord{}, false
	}
	for _, rec := range root.Completed {
		if rec.Key == key {
			return rec, true
		}
	}
	return CompletedRecord{}, false
}

func fragmentAuthority(root EvaluationRoot, id string) (string, bool) {
	for _, frag := range root.Fragments {
		if frag.FragmentID == id {
			return frag.Authority, true
		}
	}
	return "", false
}

func resolveFragments(root EvaluationRoot, ids []string) (string, int, bool) {
	effective := AuthorityUser
	n := 0
	for _, id := range ids {
		auth, ok := fragmentAuthority(root, id)
		if !ok {
			return "", n, false
		}
		n++
		if auth == AuthorityDataOnly {
			effective = AuthorityDataOnly
		}
	}
	return effective, n, true
}

func actionOK(root EvaluationRoot, a ProposedAction) bool {
	if a.ActionID == "" {
		return false
	}
	switch a.Kind {
	case KindSensitiveRead, KindEgressSend:
		return a.TaintID != "" && !taintKindExtras(a)
	case KindPrivilegedAction:
		return a.PermissionEpoch > 0 && !privilegedExtras(a)
	case KindSideEffect:
		return a.Operation != "" && a.RequestDigest != "" && !sideEffectExtras(a)
	case KindAuthoritySink:
		if a.RequiredAuthority != AuthorityUser || len(a.FragmentIDs) == 0 || !uniqueIDs(a.FragmentIDs) || sinkExtras(a) {
			return false
		}
		_, _, ok := resolveFragments(root, a.FragmentIDs)
		return ok
	default:
		return false
	}
}

func tf(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func actionWord(disp string) string {
	switch disp {
	case DispositionObserve:
		return "OBSERVED"
	case DispositionExecute:
		return "EXECUTED"
	case DispositionReplay:
		return "REPLAYED"
	default:
		return "BLOCKED"
	}
}

func renderEvidence(d Decision, f evidenceFacts) [8]string {
	enf := "disabled"
	if f.enforcementEnabled {
		enf = "enabled"
	}
	selector, match, binding := "selector=", "state=", "binding="
	switch d.Kind {
	case KindSensitiveRead, KindEgressSend:
		selector = "taint=" + d.MatchedTaint
		match = "taint_present=" + tf(f.taintPresent)
		binding = "taint_id=" + d.MatchedTaint
	case KindPrivilegedAction:
		selector = "epoch=" + strconv.Itoa(d.ActionPermissionEpoch)
		match = "current_epoch=" + strconv.Itoa(d.CurrentPermissionEpoch)
		binding = "epoch_equal=" + tf(d.ActionPermissionEpoch == d.CurrentPermissionEpoch && d.ActionPermissionEpoch > 0)
	case KindSideEffect:
		selector = "idempotency_key=" + d.IdempotencyKey
		status := "absent"
		if f.completedPresent {
			status = "present"
		}
		match = "completed=" + status
		binding = "operation_equal=" + tf(f.operationEqual) + " request_equal=" + tf(f.requestEqual)
		if d.RecordedOperation != "" || d.RecordedRequestDigest != "" {
			binding += " operation=" + d.RecordedOperation + " request=" + d.RecordedRequestDigest
		}
	case KindAuthoritySink:
		selector = "fragments=" + strings.Join(f.fragmentIDs, ",")
		match = "resolved_fragments=" + strconv.Itoa(f.resolvedFragments)
		binding = "required=" + d.RequiredAuthority + " effective=" + d.EffectiveAuthority
	}
	return [8]string{
		"schema=" + strconv.Itoa(f.schemaVersion) + " enforcement=" + enf + " action=" + d.ActionID,
		"kind=" + d.Kind + " verdict=" + d.Verdict + " disposition=" + d.Disposition,
		selector,
		match,
		binding,
		"AOEP Persistent-State Proof " + d.Proof,
		"reason " + d.Reason,
		"ACTION " + actionWord(d.Disposition),
	}
}

func populateFacts(root EvaluationRoot, action ProposedAction, d *Decision, f *evidenceFacts) {
	f.schemaVersion = root.SchemaVersion
	f.enforcementEnabled = root.EnforcementEnabled
	f.fragmentIDs = append([]string(nil), action.FragmentIDs...)
	f.taintPresent = action.TaintID != "" && hasTaint(root, action.TaintID)
	if rec, ok := findCompleted(root, action.IdempotencyKey); ok {
		f.completedPresent = true
		d.RecordedOperation = rec.Operation
		d.RecordedRequestDigest = rec.RequestDigest
		f.operationEqual = rec.Operation == action.Operation
		f.requestEqual = rec.RequestDigest == action.RequestDigest
	} else if action.Kind == KindSideEffect {
		d.RecordedOperation = action.Operation
		d.RecordedRequestDigest = action.RequestDigest
	}
	if len(action.FragmentIDs) > 0 {
		eff, n, ok := resolveFragments(root, action.FragmentIDs)
		f.resolvedFragments = n
		if ok {
			d.EffectiveAuthority = eff
		}
	}
}

func applyEnabled(root EvaluationRoot, action ProposedAction, d *Decision, f *evidenceFacts) {
	switch action.Kind {
	case KindSensitiveRead:
		d.Verdict = VerdictAllow
		d.Proof = ProofValid
		d.Disposition = DispositionObserve
		d.Reason = ReasonSensitiveSourceObserved
		d.MatchedTaint = action.TaintID
	case KindEgressSend:
		if f.taintPresent {
			d.Reason = ReasonSensitiveTaintBlocksEgress
			d.MatchedTaint = action.TaintID
			return
		}
		d.Verdict = VerdictAllow
		d.Proof = ProofValid
		d.Disposition = DispositionExecute
		d.MatchedTaint = action.TaintID
		d.Reason = ""
	case KindPrivilegedAction:
		if action.PermissionEpoch != root.CurrentPermissionEpoch {
			d.Reason = ReasonPermissionEpochStale
			return
		}
		d.Verdict = VerdictAllow
		d.Proof = ProofValid
		d.Disposition = DispositionExecute
		d.Reason = ReasonPermissionEpochCurrent
	case KindSideEffect:
		if action.IdempotencyKey == "" {
			d.Reason = ReasonIdempotencyKeyRequired
			return
		}
		rec, ok := findCompleted(root, action.IdempotencyKey)
		if !ok {
			d.Verdict = VerdictAllow
			d.Proof = ProofValid
			d.Disposition = DispositionExecute
			d.Reason = ReasonFirstSideEffectAuthorized
			return
		}
		if rec.Operation == action.Operation && rec.RequestDigest == action.RequestDigest {
			d.Verdict = VerdictAllow
			d.Proof = ProofValid
			d.Disposition = DispositionReplay
			d.Reason = ReasonCompletedResultReplayed
			d.ResultDigest = rec.ResultDigest
			return
		}
		d.Reason = ReasonIdempotencyKeyCollision
	case KindAuthoritySink:
		if d.EffectiveAuthority != AuthorityUser {
			d.Reason = ReasonUntrustedFragmentCannotAuthorizeSink
			return
		}
		d.Verdict = VerdictAllow
		d.Proof = ProofValid
		d.Disposition = DispositionExecute
		d.Reason = ReasonFragmentAuthoritySufficient
	}
}

// Authorize is a pure action-boundary oracle. It does not mutate root or
// action, invoke an executor, or update a ledger.
func Authorize(root EvaluationRoot, action ProposedAction) Decision {
	d := Decision{
		ActionID:               action.ActionID,
		Kind:                   action.Kind,
		Verdict:                VerdictDeny,
		Disposition:            DispositionBlock,
		Proof:                  ProofInvalid,
		Reason:                 ReasonInvalidRoot,
		MatchedTaint:           action.TaintID,
		ActionPermissionEpoch:  action.PermissionEpoch,
		CurrentPermissionEpoch: root.CurrentPermissionEpoch,
		IdempotencyKey:         action.IdempotencyKey,
		RequiredAuthority:      action.RequiredAuthority,
	}
	f := evidenceFacts{}
	populateFacts(root, action, &d, &f)
	switch {
	case !rootOK(root):
	case !actionOK(root, action):
		d.Reason = ReasonInvalidAction
	case !root.EnforcementEnabled:
		d.Verdict = VerdictAllow
		d.Proof = ProofDisabled
		d.Reason = ReasonEnforcementDisabled
		if action.Kind == KindSensitiveRead {
			d.Disposition = DispositionObserve
		} else {
			d.Disposition = DispositionExecute
		}
	default:
		applyEnabled(root, action, &d, &f)
	}
	d.Evidence = renderEvidence(d, f)
	return d
}
