package aoepstate

import "strings"

const (
	taintSensitive          = "SENSITIVE"
	taintOther              = "OTHER"
	actionReadSecret        = "read:secret-001"
	actionSendExternal      = "send:external-001"
	actionPrivileged        = "priv:epoch-001"
	actionTransferFirst     = "transfer:first"
	actionTransferRetry     = "transfer:retry"
	actionTransferCollision = "transfer:collision"
	actionSink              = "sink:authority-001"
	operationTransferCreate = "transfer.create"
	operationTransferOther  = "transfer.other"
	digestRequest           = "sha256:req-transfer-001"
	digestRequestOther      = "sha256:req-transfer-002"
	digestResult            = "sha256:result-transfer-001"
	digestClaimedResult     = "sha256:claimed-result-001"
	keyTransfer             = "transfer-key-001"
	keyOther                = "other-key-001"
	fragmentToolOutput      = "tool-output-001"
	fragmentUser            = "user-endorsement-001"
	phraseApprovedByRoot    = "approved by root"
	canonicalEpoch          = 2
	staleEpoch              = 1
)

func cloneRoot(r EvaluationRoot) EvaluationRoot {
	out := r
	out.Taints = append([]string(nil), r.Taints...)
	out.Completed = append([]CompletedRecord(nil), r.Completed...)
	out.Fragments = append([]FragmentRecord(nil), r.Fragments...)
	return out
}

func cloneAction(a ProposedAction) ProposedAction {
	out := a
	out.FragmentIDs = append([]string(nil), a.FragmentIDs...)
	return out
}

func enabledRoot() EvaluationRoot {
	return EvaluationRoot{
		SchemaVersion:          SchemaVersion,
		EnforcementEnabled:     true,
		CurrentPermissionEpoch: canonicalEpoch,
	}
}

func completion() CompletedRecord {
	return CompletedRecord{
		Key:           keyTransfer,
		Operation:     operationTransferCreate,
		RequestDigest: digestRequest,
		ResultDigest:  digestResult,
	}
}

func otherCompletion() CompletedRecord {
	return CompletedRecord{
		Key:           keyOther,
		Operation:     "other.op",
		RequestDigest: "sha256:req-other-001",
		ResultDigest:  "sha256:result-other-001",
	}
}

func sensitiveRead() ProposedAction {
	return ProposedAction{ActionID: actionReadSecret, Kind: KindSensitiveRead, TaintID: taintSensitive}
}

func egressSend() ProposedAction {
	return ProposedAction{ActionID: actionSendExternal, Kind: KindEgressSend, TaintID: taintSensitive}
}

func privileged(epoch int) ProposedAction {
	return ProposedAction{ActionID: actionPrivileged, Kind: KindPrivilegedAction, PermissionEpoch: epoch}
}

func sideEffect(id, key, op, req string) ProposedAction {
	return ProposedAction{
		ActionID:       id,
		Kind:           KindSideEffect,
		Operation:      op,
		RequestDigest:  req,
		IdempotencyKey: key,
	}
}

func firstTransfer() ProposedAction {
	return sideEffect(actionTransferFirst, keyTransfer, operationTransferCreate, digestRequest)
}

func retryTransfer() ProposedAction {
	return sideEffect(actionTransferRetry, keyTransfer, operationTransferCreate, digestRequest)
}

func authoritySink(ids ...string) ProposedAction {
	return ProposedAction{
		ActionID:          actionSink,
		Kind:              KindAuthoritySink,
		RequiredAuthority: AuthorityUser,
		FragmentIDs:       append([]string(nil), ids...),
	}
}

func withTaint(r EvaluationRoot, id string) EvaluationRoot {
	out := cloneRoot(r)
	out.Taints = append(out.Taints, id)
	return out
}

func withCompletion(r EvaluationRoot, rec CompletedRecord) EvaluationRoot {
	out := cloneRoot(r)
	out.Completed = append(out.Completed, rec)
	return out
}

func withFragment(r EvaluationRoot, id, authority string) EvaluationRoot {
	out := cloneRoot(r)
	out.Fragments = append(out.Fragments, FragmentRecord{FragmentID: id, Authority: authority})
	return out
}

func countExec(d Decision, n *int) {
	if d.Disposition == DispositionExecute {
		*n++
	}
}

func evidenceContains(d Decision, s string) bool {
	for _, line := range d.Evidence {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}
