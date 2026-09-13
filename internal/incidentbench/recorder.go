package incidentbench

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/themayursinha/mcp-visor/internal/incidentbundle"
)

type synthKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

func syntheticKey() *synthKey {
	sum := sha256.Sum256([]byte("mcp-visor incidentbench synthetic key v1"))
	priv := ed25519.NewKeyFromSeed(sum[:])
	pub := priv.Public().(ed25519.PublicKey)
	return &synthKey{priv: priv, pub: pub, id: "incidentbench-synthetic-" + hex.EncodeToString(pub[:8])}
}

func (k *synthKey) Sign(data []byte) ([]byte, error) { return ed25519.Sign(k.priv, data), nil }
func (k *synthKey) PublicKey() crypto.PublicKey      { return k.pub }
func (k *synthKey) KeyID() string                    { return k.id }
func (k *synthKey) Algorithm() string                { return "ed25519" }
func (k *synthKey) Verify(data, sig []byte) error {
	if !ed25519.Verify(k.pub, data, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func DedupKey(tr Trajectory) string {
	req := tr.RequestedEffect
	buf := make([]byte, 0, 128)
	buf = append(buf, tr.TrajectoryID...)
	buf = append(buf, 0)
	buf = append(buf, req.EffectID...)
	buf = append(buf, 0)
	buf = append(buf, req.Kind...)
	buf = append(buf, 0)
	buf = append(buf, req.Target...)
	buf = append(buf, 0)
	buf = append(buf, req.Tenant...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func policyHash(e PolicyAuthorityEpoch) string {
	data, _ := json.Marshal(e)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func policyID(e PolicyAuthorityEpoch) string {
	return fmt.Sprintf("incidentbench-policy-epoch-%d", e.PolicyEpoch)
}

func jsonEq(a, b any) bool {
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(ja, jb)
}

type Recorder struct {
	byKey map[string]IncidentRecord
}

func NewRecorder() *Recorder { return &Recorder{byKey: map[string]IncidentRecord{}} }

func (r *Recorder) len() int { return len(r.byKey) }

func (r *Recorder) lookup(key string) IncidentRecord { return cloneRecord(r.byKey[key]) }

func (r *Recorder) Record(tr Trajectory, res BoundaryResult) (bool, error) {
	if res.ObservedEffect.Status == "" || res.ObservedEffect.BoundarySource == "" {
		return false, fmt.Errorf("missing action-boundary observation")
	}
	if err := validateDecision(res.Decision); err != nil {
		return false, err
	}
	if err := validateObserved(res.ObservedEffect.Status); err != nil {
		return false, err
	}
	if !tr.RequestedEffect.Consequential || res.Decision != DecisionDenyOutOfAuth || !res.OutOfAuthority {
		return false, nil
	}
	_, created, err := r.PutIfAbsent(tr, res)
	return created, err
}

func (r *Recorder) PutIfAbsent(tr Trajectory, res BoundaryResult) (IncidentRecord, bool, error) {
	if !resultMatches(tr, res) {
		return IncidentRecord{}, false, fmt.Errorf("boundary result identity mismatch")
	}
	if !tr.RequestedEffect.Consequential || res.Decision != DecisionDenyOutOfAuth || !res.OutOfAuthority {
		return IncidentRecord{}, false, fmt.Errorf("ineligible incident")
	}
	key := DedupKey(tr)
	if existing, ok := r.byKey[key]; ok {
		if !equivRecord(existing, tr, res) {
			return IncidentRecord{}, false, fmt.Errorf("idempotency collision")
		}
		return cloneRecord(existing), false, nil
	}
	rec, err := buildRecord(tr, res, res.ObservedEffect.BoundaryTick+1)
	if err != nil {
		return IncidentRecord{}, false, err
	}
	if !ReceiptComplete(rec) {
		return IncidentRecord{}, false, fmt.Errorf("incomplete receipt")
	}
	r.byKey[key] = cloneRecord(rec)
	return cloneRecord(r.byKey[key]), true, nil
}

func resultMatches(tr Trajectory, res BoundaryResult) bool {
	return res.TrajectoryID == tr.TrajectoryID && res.RequestedEffect == tr.RequestedEffect &&
		res.Epoch == tr.Epoch && res.TelemetryStatus == tr.TelemetryStatus &&
		res.ObservedEffect.Kind == tr.RequestedEffect.Kind &&
		res.ObservedEffect.Target == tr.RequestedEffect.Target &&
		res.ObservedEffect.Tenant == tr.RequestedEffect.Tenant &&
		res.Reachability.FixtureID == tr.RequestedEffect.Target &&
		reflect.DeepEqual(cloneDeleg(res.DelegatedAuthority), cloneDeleg(tr.DelegatedAuthority))
}

func equivRecord(rec IncidentRecord, tr Trajectory, res BoundaryResult) bool {
	return rec.TrajectoryID == tr.TrajectoryID && rec.Decision == res.Decision && rec.Reason == res.Reason &&
		rec.RequestedEffect == tr.RequestedEffect && rec.PolicyAuthorityEpoch == res.Epoch &&
		rec.ObservedEffect == res.ObservedEffect && rec.TelemetryStatus == res.TelemetryStatus &&
		rec.ObservedReachability == res.Reachability && rec.BoundaryTick == res.ObservedEffect.BoundaryTick &&
		reflect.DeepEqual(rec.DeclaredEnvironment, cloneEnv(tr.DeclaredEnvironment)) &&
		reflect.DeepEqual(rec.DelegatedAuthority, cloneDeleg(tr.DelegatedAuthority))
}

func buildRecord(tr Trajectory, res BoundaryResult, persisted uint64) (IncidentRecord, error) {
	key := DedupKey(tr)
	rec := IncidentRecord{
		SchemaVersion: SchemaVersion, IncidentID: "incident-" + key, DedupKey: key,
		TrajectoryID: tr.TrajectoryID, DeclaredEnvironment: cloneEnv(tr.DeclaredEnvironment),
		ObservedReachability: res.Reachability, DelegatedAuthority: cloneDeleg(res.DelegatedAuthority),
		RequestedEffect: tr.RequestedEffect, ObservedEffect: res.ObservedEffect,
		PolicyAuthorityEpoch: res.Epoch, Decision: res.Decision, Reason: res.Reason,
		TelemetryStatus: res.TelemetryStatus, BoundaryTick: res.ObservedEffect.BoundaryTick,
		PersistedTick: persisted,
	}
	b, err := buildBundle(rec)
	if err != nil {
		return IncidentRecord{}, err
	}
	rec.Bundle = b
	return rec, nil
}

func appendEv(b *incidentbundle.Bundle, kind string, ts int64, rec IncidentRecord, payload map[string]any, confirm string) error {
	return b.Append(kind, ts, func(ev *incidentbundle.Event) {
		if kind == incidentbundle.KindRequestedAction {
			ev.Principal = rec.DeclaredEnvironment.Principal
			ev.Delegation = []string{rec.DelegatedAuthority.DelegationID}
			ev.AuthorityRef = rec.DelegatedAuthority.DelegationID
		}
		ev.Payload = payload
		ev.RedactionNote = RedactionNote
		ev.EvidenceSource = BoundarySource
		if confirm != "" {
			ev.Confirmation = confirm
		}
	})
}

func buildBundle(rec IncidentRecord) (*incidentbundle.Bundle, error) {
	ts := int64(rec.BoundaryTick)
	b := incidentbundle.New(rec.IncidentID, policyHash(rec.PolicyAuthorityEpoch), ts)
	b.Manifest.PolicyID = policyID(rec.PolicyAuthorityEpoch)
	if err := appendEv(b, incidentbundle.KindRequestedAction, ts, rec, map[string]any{
		"declared_environment": rec.DeclaredEnvironment, "observed_reachability": rec.ObservedReachability,
		"delegated_authority": rec.DelegatedAuthority, "requested_effect": rec.RequestedEffect,
		"policy_authority_epoch": rec.PolicyAuthorityEpoch,
	}, ""); err != nil {
		return nil, err
	}
	if err := appendEv(b, incidentbundle.KindPolicyDecision, ts+1, rec, map[string]any{
		"decision": "deny", "reason": rec.Reason, "policy_epoch": rec.PolicyAuthorityEpoch.PolicyEpoch,
		"authority_epoch": rec.PolicyAuthorityEpoch.AuthorityEpoch, "authority_valid": false,
	}, ""); err != nil {
		return nil, err
	}
	if err := appendEv(b, incidentbundle.KindRuntimeAttempt, ts+2, rec, map[string]any{
		"relayed": false, "blocked_at": Coverage,
	}, ""); err != nil {
		return nil, err
	}
	if err := appendEv(b, incidentbundle.KindExternalEffect, ts+3, rec, map[string]any{
		"observed_effect": rec.ObservedEffect, "telemetry_status": rec.TelemetryStatus,
	}, incidentbundle.ConfirmationConfirmed); err != nil {
		return nil, err
	}
	if err := b.Seal(syntheticKey()); err != nil {
		return nil, err
	}
	return b, nil
}

func ReceiptComplete(rec IncidentRecord) bool {
	if rec.SchemaVersion != SchemaVersion || rec.IncidentID == "" || rec.DedupKey == "" || rec.TrajectoryID == "" {
		return false
	}
	if rec.IncidentID != "incident-"+rec.DedupKey || rec.Decision != DecisionDenyOutOfAuth || rec.Reason == "" {
		return false
	}
	if rec.ObservedEffect.Status != ObservedBlocked || rec.ObservedEffect.BoundarySource != BoundarySource {
		return false
	}
	if rec.PersistedTick != rec.BoundaryTick+1 || rec.BoundaryTick == 0 {
		return false
	}
	if rec.TelemetryStatus != TelemetryPresent && rec.TelemetryStatus != TelemetryMissing {
		return false
	}
	if rec.RequestedEffect.Kind == "" || rec.DeclaredEnvironment.Principal == "" {
		return false
	}
	b := rec.Bundle
	if b == nil || len(b.Events) != 4 {
		return false
	}
	if b.Manifest.BundleID != rec.IncidentID || b.Manifest.PolicyID != policyID(rec.PolicyAuthorityEpoch) ||
		b.Manifest.PolicyHash != policyHash(rec.PolicyAuthorityEpoch) {
		return false
	}
	want := [...]string{incidentbundle.KindRequestedAction, incidentbundle.KindPolicyDecision, incidentbundle.KindRuntimeAttempt, incidentbundle.KindExternalEffect}
	for i, k := range want {
		if b.Events[i].Kind != k {
			return false
		}
	}
	p0 := b.Events[0].Payload
	if !jsonEq(p0["declared_environment"], rec.DeclaredEnvironment) || !jsonEq(p0["observed_reachability"], rec.ObservedReachability) ||
		!jsonEq(p0["delegated_authority"], rec.DelegatedAuthority) || !jsonEq(p0["requested_effect"], rec.RequestedEffect) ||
		!jsonEq(p0["policy_authority_epoch"], rec.PolicyAuthorityEpoch) {
		return false
	}
	p1 := b.Events[1].Payload
	if p1["decision"] != "deny" || p1["authority_valid"] != false || !jsonEq(p1["reason"], rec.Reason) {
		return false
	}
	p2 := b.Events[2].Payload
	if p2["relayed"] != false || p2["blocked_at"] != Coverage {
		return false
	}
	p3 := b.Events[3].Payload
	if !jsonEq(p3["observed_effect"], rec.ObservedEffect) || !jsonEq(p3["telemetry_status"], rec.TelemetryStatus) {
		return false
	}
	if b.Events[3].Confirmation != incidentbundle.ConfirmationConfirmed {
		return false
	}
	return b.Verify(syntheticKey()) == nil
}
