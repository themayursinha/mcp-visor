package aoepstate

import (
	"reflect"
	"testing"
)

func assertUnchanged(t *testing.T, root, rootBefore EvaluationRoot, action, actionBefore ProposedAction) {
	t.Helper()
	if !reflect.DeepEqual(root, rootBefore) || !reflect.DeepEqual(action, actionBefore) {
		t.Fatal("caller-held state mutated")
	}
}

func assertDecision(t *testing.T, d Decision, verdict, proof, disp, reason string) {
	t.Helper()
	if d.Verdict != verdict || d.Proof != proof || d.Disposition != disp || d.Reason != reason {
		t.Fatalf("got verdict=%s proof=%s disposition=%s reason=%s", d.Verdict, d.Proof, d.Disposition, d.Reason)
	}
}

func TestRedSensitiveReadTaintBlocksLaterEgress(t *testing.T) {
	root := enabledRoot()
	rootBefore := cloneRoot(root)
	read := sensitiveRead()
	readBefore := cloneAction(read)
	exec := 0
	d1 := Authorize(root, read)
	countExec(d1, &exec)
	assertUnchanged(t, root, rootBefore, read, readBefore)
	assertDecision(t, d1, VerdictAllow, ProofValid, DispositionObserve, ReasonSensitiveSourceObserved)
	if d1.MatchedTaint != taintSensitive || exec != 0 {
		t.Fatalf("observe %+v exec=%d", d1, exec)
	}

	tainted := withTaint(root, taintSensitive)
	send := egressSend()
	sendBefore := cloneAction(send)
	taintedBefore := cloneRoot(tainted)
	d2 := Authorize(tainted, send)
	countExec(d2, &exec)
	assertUnchanged(t, root, rootBefore, send, sendBefore)
	assertUnchanged(t, tainted, taintedBefore, send, sendBefore)
	assertDecision(t, d2, VerdictDeny, ProofInvalid, DispositionBlock, ReasonSensitiveTaintBlocksEgress)
	if exec != 0 || d2.MatchedTaint != taintSensitive {
		t.Fatalf("blocked egress %+v exec=%d", d2, exec)
	}
	want := [8]string{
		"schema=1 enforcement=enabled action=" + actionSendExternal,
		"kind=EGRESS_SEND verdict=DENY disposition=BLOCK",
		"taint=" + taintSensitive,
		"taint_present=true",
		"taint_id=" + taintSensitive,
		"AOEP Persistent-State Proof INVALID",
		"reason " + ReasonSensitiveTaintBlocksEgress,
		"ACTION BLOCKED",
	}
	if d2.Evidence != want {
		t.Fatalf("evidence %+v", d2.Evidence)
	}
}

func TestEgressBeforeTaintAllows(t *testing.T) {
	root := enabledRoot()
	rootBefore := cloneRoot(root)
	send := egressSend()
	sendBefore := cloneAction(send)
	exec := 0
	d := Authorize(root, send)
	countExec(d, &exec)
	assertUnchanged(t, root, rootBefore, send, sendBefore)
	if d.Verdict != VerdictAllow || d.Proof != ProofValid || d.Disposition != DispositionExecute || exec != 1 {
		t.Fatalf("got %+v exec=%d", d, exec)
	}
}

func TestRedStalePermissionEpochDenied(t *testing.T) {
	root := enabledRoot()
	rootBefore := cloneRoot(root)
	action := privileged(staleEpoch)
	action.ClaimedCurrentEpoch = canonicalEpoch
	action.ClaimedAuthorization = "authorized"
	before := cloneAction(action)
	exec := 0
	d := Authorize(root, action)
	countExec(d, &exec)
	assertUnchanged(t, root, rootBefore, action, before)
	assertDecision(t, d, VerdictDeny, ProofInvalid, DispositionBlock, ReasonPermissionEpochStale)
	if exec != 0 || d.ActionPermissionEpoch != staleEpoch || d.CurrentPermissionEpoch != canonicalEpoch {
		t.Fatalf("stale %+v exec=%d", d, exec)
	}
	want := [8]string{
		"schema=1 enforcement=enabled action=" + actionPrivileged,
		"kind=PRIVILEGED_ACTION verdict=DENY disposition=BLOCK",
		"epoch=1",
		"current_epoch=2",
		"epoch_equal=false",
		"AOEP Persistent-State Proof INVALID",
		"reason " + ReasonPermissionEpochStale,
		"ACTION BLOCKED",
	}
	if d.Evidence != want {
		t.Fatalf("evidence %+v", d.Evidence)
	}
	if evidenceContains(d, "authorized") {
		t.Fatal("claimed authorization in evidence")
	}
}

func TestCurrentPermissionEpochAllows(t *testing.T) {
	root := enabledRoot()
	action := privileged(canonicalEpoch)
	exec := 0
	d := Authorize(root, action)
	countExec(d, &exec)
	assertDecision(t, d, VerdictAllow, ProofValid, DispositionExecute, ReasonPermissionEpochCurrent)
	if exec != 1 {
		t.Fatalf("exec=%d", exec)
	}
}

func TestRedCompletedIdempotencyKeyDoesNotExecuteTwice(t *testing.T) {
	root := enabledRoot()
	rootBefore := cloneRoot(root)
	first := firstTransfer()
	firstBefore := cloneAction(first)
	exec := 0
	d1 := Authorize(root, first)
	countExec(d1, &exec)
	assertUnchanged(t, root, rootBefore, first, firstBefore)
	assertDecision(t, d1, VerdictAllow, ProofValid, DispositionExecute, ReasonFirstSideEffectAuthorized)
	if exec != 1 || d1.ResultDigest != "" {
		t.Fatalf("first %+v exec=%d", d1, exec)
	}
	wantFirst := [8]string{
		"schema=1 enforcement=enabled action=" + actionTransferFirst,
		"kind=SIDE_EFFECT verdict=ALLOW disposition=EXECUTE",
		"idempotency_key=" + keyTransfer,
		"completed=absent",
		"operation_equal=false request_equal=false operation=" + operationTransferCreate + " request=" + digestRequest,
		"AOEP Persistent-State Proof VALID",
		"reason " + ReasonFirstSideEffectAuthorized,
		"ACTION EXECUTED",
	}
	if d1.Evidence != wantFirst {
		t.Fatalf("first evidence %+v", d1.Evidence)
	}

	completed := withCompletion(root, completion())
	completedBefore := cloneRoot(completed)
	retry := retryTransfer()
	retryBefore := cloneAction(retry)
	d2 := Authorize(completed, retry)
	countExec(d2, &exec)
	assertUnchanged(t, root, rootBefore, retry, retryBefore)
	assertUnchanged(t, completed, completedBefore, first, firstBefore)
	assertDecision(t, d2, VerdictAllow, ProofValid, DispositionReplay, ReasonCompletedResultReplayed)
	if exec != 1 || d2.ResultDigest != digestResult {
		t.Fatalf("retry %+v exec=%d", d2, exec)
	}
	wantReplay := [8]string{
		"schema=1 enforcement=enabled action=" + actionTransferRetry,
		"kind=SIDE_EFFECT verdict=ALLOW disposition=REPLAY",
		"idempotency_key=" + keyTransfer,
		"completed=present",
		"operation_equal=true request_equal=true operation=" + operationTransferCreate + " request=" + digestRequest,
		"AOEP Persistent-State Proof VALID",
		"reason " + ReasonCompletedResultReplayed,
		"ACTION REPLAYED",
	}
	if d2.Evidence != wantReplay {
		t.Fatalf("replay evidence %+v", d2.Evidence)
	}
}

func TestExactCompletedRetryReplaysCallerHeldResult(t *testing.T) {
	root := withCompletion(enabledRoot(), completion())
	rootBefore := cloneRoot(root)
	retry := retryTransfer()
	retry.ClaimedResultDigest = digestClaimedResult
	retry.ClaimedReplay = true
	before := cloneAction(retry)
	exec := 0
	d := Authorize(root, retry)
	countExec(d, &exec)
	assertUnchanged(t, root, rootBefore, retry, before)
	assertDecision(t, d, VerdictAllow, ProofValid, DispositionReplay, ReasonCompletedResultReplayed)
	if d.ResultDigest != digestResult || exec != 0 {
		t.Fatalf("replay %+v exec=%d", d, exec)
	}
	want := [8]string{
		"schema=1 enforcement=enabled action=" + actionTransferRetry,
		"kind=SIDE_EFFECT verdict=ALLOW disposition=REPLAY",
		"idempotency_key=" + keyTransfer,
		"completed=present",
		"operation_equal=true request_equal=true operation=" + operationTransferCreate + " request=" + digestRequest,
		"AOEP Persistent-State Proof VALID",
		"reason " + ReasonCompletedResultReplayed,
		"ACTION REPLAYED",
	}
	if d.Evidence != want {
		t.Fatalf("evidence %+v", d.Evidence)
	}
	if evidenceContains(d, digestClaimedResult) {
		t.Fatal("claimed result digest in evidence")
	}
}

func TestIdempotencyKeyCollisionDenied(t *testing.T) {
	root := withCompletion(enabledRoot(), completion())
	exec := 0
	op := sideEffect(actionTransferCollision, keyTransfer, operationTransferOther, digestRequest)
	dOp := Authorize(root, op)
	countExec(dOp, &exec)
	assertDecision(t, dOp, VerdictDeny, ProofInvalid, DispositionBlock, ReasonIdempotencyKeyCollision)
	wantOp := [8]string{
		"schema=1 enforcement=enabled action=" + actionTransferCollision,
		"kind=SIDE_EFFECT verdict=DENY disposition=BLOCK",
		"idempotency_key=" + keyTransfer,
		"completed=present",
		"operation_equal=false request_equal=true operation=" + operationTransferCreate + " request=" + digestRequest,
		"AOEP Persistent-State Proof INVALID",
		"reason " + ReasonIdempotencyKeyCollision,
		"ACTION BLOCKED",
	}
	if dOp.Evidence != wantOp {
		t.Fatalf("op evidence %+v", dOp.Evidence)
	}

	req := sideEffect(actionTransferCollision, keyTransfer, operationTransferCreate, digestRequestOther)
	req.ClaimedResultDigest = digestResult
	req.ClaimedReplay = true
	dReq := Authorize(root, req)
	countExec(dReq, &exec)
	assertDecision(t, dReq, VerdictDeny, ProofInvalid, DispositionBlock, ReasonIdempotencyKeyCollision)
	if dReq.Disposition == DispositionReplay || dReq.ResultDigest != "" || exec != 0 {
		t.Fatalf("digest collision %+v exec=%d", dReq, exec)
	}
	wantReq := [8]string{
		"schema=1 enforcement=enabled action=" + actionTransferCollision,
		"kind=SIDE_EFFECT verdict=DENY disposition=BLOCK",
		"idempotency_key=" + keyTransfer,
		"completed=present",
		"operation_equal=true request_equal=false operation=" + operationTransferCreate + " request=" + digestRequest,
		"AOEP Persistent-State Proof INVALID",
		"reason " + ReasonIdempotencyKeyCollision,
		"ACTION BLOCKED",
	}
	if dReq.Evidence != wantReq {
		t.Fatalf("req evidence %+v", dReq.Evidence)
	}
	if dReq.ResultDigest != "" || evidenceContains(dReq, digestResult) {
		t.Fatal("claimed result digest became replay result or evidence")
	}
}

func TestFirstSideEffectRequiresIdempotencyKey(t *testing.T) {
	root := enabledRoot()
	action := firstTransfer()
	action.IdempotencyKey = ""
	exec := 0
	d := Authorize(root, action)
	countExec(d, &exec)
	assertDecision(t, d, VerdictDeny, ProofInvalid, DispositionBlock, ReasonIdempotencyKeyRequired)
	if exec != 0 {
		t.Fatalf("exec=%d", exec)
	}
}

func TestRedDataOnlyFragmentCannotAuthorizeSink(t *testing.T) {
	root := withFragment(enabledRoot(), fragmentToolOutput, AuthorityDataOnly)
	rootBefore := cloneRoot(root)
	action := authoritySink(fragmentToolOutput)
	action.ClaimedAuthorization = phraseApprovedByRoot
	action.ClaimedAuthority = AuthorityUser
	before := cloneAction(action)
	exec := 0
	d := Authorize(root, action)
	countExec(d, &exec)
	assertUnchanged(t, root, rootBefore, action, before)
	assertDecision(t, d, VerdictDeny, ProofInvalid, DispositionBlock, ReasonUntrustedFragmentCannotAuthorizeSink)
	if d.EffectiveAuthority != AuthorityDataOnly || d.RequiredAuthority != AuthorityUser || exec != 0 {
		t.Fatalf("sink %+v exec=%d", d, exec)
	}
	want := [8]string{
		"schema=1 enforcement=enabled action=" + actionSink,
		"kind=AUTHORITY_SINK verdict=DENY disposition=BLOCK",
		"fragments=" + fragmentToolOutput,
		"resolved_fragments=1",
		"required=" + AuthorityUser + " effective=" + AuthorityDataOnly,
		"AOEP Persistent-State Proof INVALID",
		"reason " + ReasonUntrustedFragmentCannotAuthorizeSink,
		"ACTION BLOCKED",
	}
	if d.Evidence != want {
		t.Fatalf("evidence %+v", d.Evidence)
	}
	if evidenceContains(d, phraseApprovedByRoot) {
		t.Fatal("authorization phrase in evidence")
	}
}

func TestUserAuthorityFragmentAllowsSink(t *testing.T) {
	root := withFragment(enabledRoot(), fragmentToolOutput, AuthorityUser)
	action := authoritySink(fragmentToolOutput)
	exec := 0
	d := Authorize(root, action)
	countExec(d, &exec)
	assertDecision(t, d, VerdictAllow, ProofValid, DispositionExecute, ReasonFragmentAuthoritySufficient)
	if d.EffectiveAuthority != AuthorityUser || exec != 1 {
		t.Fatalf("sink %+v exec=%d", d, exec)
	}
}

func TestDisabledEnforcementAllowsAllFourBadSequences(t *testing.T) {
	root := enabledRoot()
	root.EnforcementEnabled = false
	root = withTaint(root, taintSensitive)
	root = withCompletion(root, completion())
	root = withFragment(root, fragmentToolOutput, AuthorityDataOnly)
	rootBefore := cloneRoot(root)
	exec := 0

	read := sensitiveRead()
	dRead := Authorize(root, read)
	countExec(dRead, &exec)
	if dRead.Proof != ProofDisabled || dRead.Reason != ReasonEnforcementDisabled || dRead.Disposition != DispositionObserve || dRead.Verdict != VerdictAllow {
		t.Fatalf("read %+v", dRead)
	}

	send := egressSend()
	dSend := Authorize(root, send)
	countExec(dSend, &exec)
	if dSend.Proof != ProofDisabled || dSend.Verdict != VerdictAllow || dSend.Disposition != DispositionExecute {
		t.Fatalf("egress %+v", dSend)
	}
	wantDisabled := [8]string{
		"schema=1 enforcement=disabled action=" + actionSendExternal,
		"kind=EGRESS_SEND verdict=ALLOW disposition=EXECUTE",
		"taint=" + taintSensitive,
		"taint_present=true",
		"taint_id=" + taintSensitive,
		"AOEP Persistent-State Proof DISABLED",
		"reason " + ReasonEnforcementDisabled,
		"ACTION EXECUTED",
	}
	if dSend.Evidence != wantDisabled {
		t.Fatalf("disabled evidence %+v", dSend.Evidence)
	}

	stale := privileged(staleEpoch)
	dStale := Authorize(root, stale)
	countExec(dStale, &exec)
	if dStale.Proof != ProofDisabled || dStale.Verdict != VerdictAllow || dStale.Disposition != DispositionExecute {
		t.Fatalf("stale %+v", dStale)
	}

	retry := retryTransfer()
	dRetry := Authorize(root, retry)
	countExec(dRetry, &exec)
	if dRetry.Proof != ProofDisabled || dRetry.Verdict != VerdictAllow || dRetry.Disposition != DispositionExecute || dRetry.Disposition == DispositionReplay || dRetry.ResultDigest != "" {
		t.Fatalf("retry %+v", dRetry)
	}

	sink := authoritySink(fragmentToolOutput)
	dSink := Authorize(root, sink)
	countExec(dSink, &exec)
	if dSink.Proof != ProofDisabled || dSink.Verdict != VerdictAllow || dSink.Disposition != DispositionExecute {
		t.Fatalf("sink %+v", dSink)
	}

	assertUnchanged(t, root, rootBefore, send, cloneAction(send))
	if exec != 4 {
		t.Fatalf("expected four unsafe EXECUTE dispositions, got %d", exec)
	}
}

func TestUntrustedClaimsCannotChangeEnabledDecisions(t *testing.T) {
	type pair struct {
		root    EvaluationRoot
		plain   ProposedAction
		claimed ProposedAction
	}
	egressRoot := withTaint(enabledRoot(), taintSensitive)
	plainEgress, claimedEgress := egressSend(), egressSend()
	claimedEgress.ClaimedAuthorization = phraseApprovedByRoot
	claimedEgress.ClaimedAuthority = AuthorityUser
	claimedEgress.ClaimedReplay = true

	plainPriv, claimedPriv := privileged(staleEpoch), privileged(staleEpoch)
	claimedPriv.ClaimedCurrentEpoch = canonicalEpoch
	claimedPriv.ClaimedAuthorization = "authorized"

	replayRoot := withCompletion(enabledRoot(), completion())
	plainRetry, claimedRetry := retryTransfer(), retryTransfer()
	claimedRetry.ClaimedResultDigest = digestClaimedResult
	claimedRetry.ClaimedReplay = true
	claimedRetry.ClaimedAuthorization = phraseApprovedByRoot

	sinkRoot := withFragment(enabledRoot(), fragmentToolOutput, AuthorityDataOnly)
	plainSink, claimedSink := authoritySink(fragmentToolOutput), authoritySink(fragmentToolOutput)
	claimedSink.ClaimedAuthorization = phraseApprovedByRoot
	claimedSink.ClaimedAuthority = AuthorityUser

	for _, p := range []pair{
		{egressRoot, plainEgress, claimedEgress},
		{enabledRoot(), plainPriv, claimedPriv},
		{replayRoot, plainRetry, claimedRetry},
		{sinkRoot, plainSink, claimedSink},
	} {
		d1, d2 := Authorize(p.root, p.plain), Authorize(p.root, p.claimed)
		if d1.Verdict != d2.Verdict || d1.Proof != d2.Proof || d1.Disposition != d2.Disposition || d1.Reason != d2.Reason || d1.ResultDigest != d2.ResultDigest || d1.EffectiveAuthority != d2.EffectiveAuthority || d1.Evidence != d2.Evidence {
			t.Fatalf("claims changed decision\nplain=%+v\nclaimed=%+v", d1, d2)
		}
		if evidenceContains(d2, phraseApprovedByRoot) || evidenceContains(d2, digestClaimedResult) {
			t.Fatal("claims leaked into evidence")
		}
	}
}

func TestClaimedResultDigestCannotChangeReplayResult(t *testing.T) {
	root := withCompletion(enabledRoot(), completion())
	retry := retryTransfer()
	retry.ClaimedResultDigest = digestClaimedResult
	d := Authorize(root, retry)
	if d.Disposition != DispositionReplay || d.ResultDigest != digestResult {
		t.Fatalf("replay %+v", d)
	}
	if evidenceContains(d, digestClaimedResult) {
		t.Fatal("claimed digest in evidence")
	}

	collision := sideEffect(actionTransferCollision, keyTransfer, operationTransferOther, digestRequest)
	collision.ClaimedResultDigest = digestResult
	collision.ClaimedReplay = true
	c := Authorize(root, collision)
	if c.Disposition != DispositionBlock || c.Reason != ReasonIdempotencyKeyCollision || c.ResultDigest != "" {
		t.Fatalf("collision %+v", c)
	}
}

func TestAuthorizeIsPureAndDeterministic(t *testing.T) {
	root := withTaint(withCompletion(withFragment(enabledRoot(), fragmentToolOutput, AuthorityDataOnly), completion()), taintSensitive)
	actions := []ProposedAction{sensitiveRead(), egressSend(), privileged(staleEpoch), firstTransfer(), retryTransfer(), authoritySink(fragmentToolOutput)}
	for i, a := range actions {
		rootBefore := cloneRoot(root)
		actionBefore := cloneAction(a)
		d1 := Authorize(root, a)
		d2 := Authorize(root, a)
		assertUnchanged(t, root, rootBefore, a, actionBefore)
		if !reflect.DeepEqual(d1, d2) {
			t.Fatalf("nondeterministic %d %+v %+v", i, d1, d2)
		}
	}
}

func TestSequentialTrajectoriesDoNotBleedState(t *testing.T) {
	taintRoot := enabledRoot()
	dRead := Authorize(taintRoot, sensitiveRead())
	if dRead.Disposition != DispositionObserve {
		t.Fatalf("read %+v", dRead)
	}
	if len(taintRoot.Taints) != 0 {
		t.Fatal("taint bled onto caller root")
	}
	if Authorize(enabledRoot(), egressSend()).Disposition != DispositionExecute {
		t.Fatal("clean egress after prior read")
	}

	stale := Authorize(enabledRoot(), privileged(staleEpoch))
	current := Authorize(enabledRoot(), privileged(canonicalEpoch))
	if stale.Disposition != DispositionBlock || current.Disposition != DispositionExecute {
		t.Fatalf("epoch bleed stale=%+v current=%+v", stale, current)
	}

	first := Authorize(enabledRoot(), firstTransfer())
	replay := Authorize(withCompletion(enabledRoot(), completion()), retryTransfer())
	fresh := Authorize(enabledRoot(), firstTransfer())
	if first.Disposition != DispositionExecute || replay.Disposition != DispositionReplay || fresh.Disposition != DispositionExecute {
		t.Fatalf("idempotency bleed first=%+v replay=%+v fresh=%+v", first, replay, fresh)
	}

	deny := Authorize(withFragment(enabledRoot(), fragmentToolOutput, AuthorityDataOnly), authoritySink(fragmentToolOutput))
	allow := Authorize(withFragment(enabledRoot(), fragmentToolOutput, AuthorityUser), authoritySink(fragmentToolOutput))
	if deny.Disposition != DispositionBlock || allow.Disposition != DispositionExecute {
		t.Fatalf("fragment bleed deny=%+v allow=%+v", deny, allow)
	}
}

func TestRootSetOrderingDoesNotChangeDecision(t *testing.T) {
	base := enabledRoot()
	base.Taints = []string{taintOther, taintSensitive}
	base.Completed = []CompletedRecord{otherCompletion(), completion()}
	base.Fragments = []FragmentRecord{
		{FragmentID: fragmentUser, Authority: AuthorityUser},
		{FragmentID: fragmentToolOutput, Authority: AuthorityDataOnly},
	}
	reversed := cloneRoot(base)
	reversed.Taints = []string{taintSensitive, taintOther}
	reversed.Completed = []CompletedRecord{completion(), otherCompletion()}
	reversed.Fragments = []FragmentRecord{
		{FragmentID: fragmentToolOutput, Authority: AuthorityDataOnly},
		{FragmentID: fragmentUser, Authority: AuthorityUser},
	}
	actions := []ProposedAction{
		egressSend(),
		retryTransfer(),
		authoritySink(fragmentToolOutput),
		authoritySink(fragmentUser, fragmentToolOutput),
	}
	for _, a := range actions {
		d1, d2 := Authorize(base, a), Authorize(reversed, a)
		if !reflect.DeepEqual(d1, d2) {
			t.Fatalf("order changed %s\n%+v\n%+v", a.Kind, d1, d2)
		}
	}
}

func TestStructuralValidationFailsClosed(t *testing.T) {
	send := egressSend()
	invalidRoot := func(name string, mut func(*EvaluationRoot)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			r := enabledRoot()
			mut(&r)
			d := Authorize(r, send)
			if d.Reason != ReasonInvalidRoot || d.Proof != ProofInvalid || d.Disposition != DispositionBlock || d.Verdict != VerdictDeny {
				t.Fatalf("%s %+v", name, d)
			}
			if d.Evidence[5] != "AOEP Persistent-State Proof INVALID" || d.Evidence[7] != "ACTION BLOCKED" {
				t.Fatalf("evidence %+v", d.Evidence)
			}
		})
	}
	invalidRoot("schema mismatch", func(r *EvaluationRoot) { r.SchemaVersion = 2 })
	invalidRoot("zero permission epoch", func(r *EvaluationRoot) { r.CurrentPermissionEpoch = 0 })
	invalidRoot("empty taint", func(r *EvaluationRoot) { r.Taints = []string{""} })
	invalidRoot("duplicate taint", func(r *EvaluationRoot) { r.Taints = []string{taintSensitive, taintSensitive} })
	invalidRoot("incomplete completed record", func(r *EvaluationRoot) {
		r.Completed = []CompletedRecord{{Key: keyTransfer, Operation: operationTransferCreate, RequestDigest: digestRequest}}
	})
	invalidRoot("duplicate completed keys", func(r *EvaluationRoot) {
		r.Completed = []CompletedRecord{completion(), completion()}
	})
	invalidRoot("empty fragment id", func(r *EvaluationRoot) {
		r.Fragments = []FragmentRecord{{FragmentID: "", Authority: AuthorityUser}}
	})
	invalidRoot("duplicate fragment id", func(r *EvaluationRoot) {
		r.Fragments = []FragmentRecord{
			{FragmentID: fragmentToolOutput, Authority: AuthorityDataOnly},
			{FragmentID: fragmentToolOutput, Authority: AuthorityUser},
		}
	})
	invalidRoot("unknown fragment authority", func(r *EvaluationRoot) {
		r.Fragments = []FragmentRecord{{FragmentID: fragmentToolOutput, Authority: "SYSTEM"}}
	})

	disabledMalformed := enabledRoot()
	disabledMalformed.EnforcementEnabled = false
	disabledMalformed.SchemaVersion = 0
	dDisabled := Authorize(disabledMalformed, send)
	if dDisabled.Proof != ProofInvalid || dDisabled.Reason != ReasonInvalidRoot || dDisabled.Disposition != DispositionBlock {
		t.Fatalf("malformed disabled %+v", dDisabled)
	}

	invalidAction := func(name string, mut func(*ProposedAction)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			a := send
			mut(&a)
			d := Authorize(enabledRoot(), a)
			if d.Reason != ReasonInvalidAction || d.Proof != ProofInvalid || d.Disposition != DispositionBlock {
				t.Fatalf("%s %+v", name, d)
			}
		})
	}
	invalidAction("empty action id", func(a *ProposedAction) { a.ActionID = "" })
	invalidAction("unknown action kind", func(a *ProposedAction) { a.Kind = "UNKNOWN" })
	invalidAction("mixed-kind taint with epoch", func(a *ProposedAction) { a.PermissionEpoch = canonicalEpoch })
	invalidAction("mixed-kind taint with operation", func(a *ProposedAction) { a.Operation = operationTransferCreate })
	invalidAction("empty taint id", func(a *ProposedAction) { a.TaintID = "" })

	priv := privileged(canonicalEpoch)
	priv.TaintID = taintSensitive
	if Authorize(enabledRoot(), priv).Reason != ReasonInvalidAction {
		t.Fatal("mixed privileged")
	}
	side := firstTransfer()
	side.TaintID = taintSensitive
	if Authorize(enabledRoot(), side).Reason != ReasonInvalidAction {
		t.Fatal("mixed side effect")
	}
	sideEmpty := firstTransfer()
	sideEmpty.Operation = ""
	if Authorize(enabledRoot(), sideEmpty).Reason != ReasonInvalidAction {
		t.Fatal("incomplete side effect")
	}

	sink := authoritySink(fragmentToolOutput, fragmentToolOutput)
	if Authorize(withFragment(enabledRoot(), fragmentToolOutput, AuthorityUser), sink).Reason != ReasonInvalidAction {
		t.Fatal("duplicate sink refs")
	}
	emptyRef := authoritySink("")
	if Authorize(enabledRoot(), emptyRef).Reason != ReasonInvalidAction {
		t.Fatal("empty sink ref")
	}
	missing := authoritySink(fragmentToolOutput)
	if Authorize(enabledRoot(), missing).Reason != ReasonInvalidAction {
		t.Fatal("missing fragment")
	}
	sinkExtra := authoritySink(fragmentToolOutput)
	sinkExtra.Operation = operationTransferCreate
	if Authorize(withFragment(enabledRoot(), fragmentToolOutput, AuthorityUser), sinkExtra).Reason != ReasonInvalidAction {
		t.Fatal("mixed sink")
	}
	sinkReq := authoritySink(fragmentToolOutput)
	sinkReq.RequiredAuthority = AuthorityDataOnly
	if Authorize(withFragment(enabledRoot(), fragmentToolOutput, AuthorityUser), sinkReq).Reason != ReasonInvalidAction {
		t.Fatal("sink required authority")
	}
}
