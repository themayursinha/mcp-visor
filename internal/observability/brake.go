// Package observability — brake metrics v0.1.
//
// Brake metrics count what the enforcement point already decided:
// measurement only, never authorization. Every metric maps to an exact
// audit event type and field, or is explicitly marked not computable with
// the missing field named. See docs/brake-metrics.md for the contract
// table, computability audit, and gap list.
//
// Invariants (card t_7339cc81):
//  1. Metric names live here exactly once; docs reference but never
//     redefine them.
//  2. No metric reads agent-writable data; inputs are audit-log records
//     from the append-only sink.
//  3. Deterministic: same fixture in, same numbers out. No sampling.
package observability

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

// Brake metric names (v0.1). Single source of truth.
const (
	// MetricDeniedTotal counts policy denials at the action boundary.
	MetricDeniedTotal = "brake.denied_total"
	// MetricDeniedByRule breaks denials down by the firing policy rule.
	MetricDeniedByRule = "brake.denied_by_rule"
	// MetricDeniedNoRule counts denials recorded without a policy rule.
	// Separate counter (never an in-band sentinel value) so no legal rule
	// name can collide with it.
	MetricDeniedNoRule = "brake.denied_no_rule"
	// MetricApprovalGatesTotal counts calls held for human approval.
	MetricApprovalGatesTotal = "brake.approval_gates_total"
	// MetricApprovalGrantsTotal counts holds resolved by human grant,
	// joined to the hold by request hash.
	MetricApprovalGrantsTotal = "brake.approval_grants_total"
	// MetricApprovalOverridesTotal counts holds resolved without a grant
	// receipt (bypassed or decided off-record).
	// NOT COMPUTABLE TODAY: bypasses leave no outcome event.
	MetricApprovalOverridesTotal = "brake.approval_overrides_total"
	// MetricChainInterceptsTotal counts chain-rule interceptions.
	MetricChainInterceptsTotal = "brake.chain_intercepts_total"
	// MetricTaintBlocksTotal counts denials on tainted sessions.
	MetricTaintBlocksTotal = "brake.taint_blocks_total"
	// MetricUnloggedDenialsTotal counts declared terminal decisions with
	// no matching audit event (reconciliation gaps).
	MetricUnloggedDenialsTotal = "brake.unlogged_denials_total"
)

// Computability marks whether a metric derives from fields that exist.
type Computability string

const (
	// ComputableToday derives from current event types and fields.
	ComputableToday Computability = "computable_today"
	// NeedsNewField names a missing event or field in the gap list.
	NeedsNewField Computability = "needs_new_field"
)

// MetricDef binds one metric to its source vocabulary.
type MetricDef struct {
	Name          string
	Definition    string
	SourceEvent   string
	SourceField   string
	Computability Computability
	Gap           string
}

// Contract is the machine-readable v0.1 metric contract.
var Contract = []MetricDef{
	{
		Name:          MetricDeniedTotal,
		Definition:    "Terminal policy denials at the tools/call boundary per log scope.",
		SourceEvent:   string(audit.EventToolDenied),
		SourceField:   "event_type",
		Computability: ComputableToday,
	},
	{
		Name:          MetricDeniedByRule,
		Definition:    "Denials grouped by recorded policy rule; rule-less denials ride the separate denied_no_rule counter (no in-band sentinel can collide with a legal rule name, and free-form reasons are never folded in).",
		SourceEvent:   string(audit.EventToolDenied),
		SourceField:   "policy_rule",
		Computability: ComputableToday,
		Gap:           "Open refinement: a stable rule identifier on every deny path so denied_no_rule shrinks to zero.",
	},
	{
		Name:          MetricDeniedNoRule,
		Definition:    "Denials recorded without a policy rule (separate counter; see denied_by_rule).",
		SourceEvent:   string(audit.EventToolDenied),
		SourceField:   "(absence of policy_rule)",
		Computability: ComputableToday,
	},
	{
		Name:          MetricApprovalGatesTotal,
		Definition:    "Calls held for human approval.",
		SourceEvent:   string(audit.EventToolApprovalRequired),
		SourceField:   "event_type",
		Computability: ComputableToday,
	},
	{
		Name:          MetricApprovalGrantsTotal,
		Definition:    "Holds resolved by human grant: allowed with a receipt hash whose request hash matches a preceding hold (capability-accounted allows share the receipt field and never count); each hold satisfies one grant.",
		SourceEvent:   string(audit.EventToolAllowed),
		SourceField:   "approval_receipt_hash",
		Computability: ComputableToday,
	},
	{
		Name:          MetricApprovalOverridesTotal,
		Definition:    "Holds resolved without a grant receipt (bypassed or decided off-record).",
		SourceEvent:   "(no bypass/override outcome event exists)",
		SourceField:   "approval_outcome",
		Computability: NeedsNewField,
		Gap:           "Emit tool_call_approved / tool_call_approval_overridden with outcome + receipt hash; see docs/brake-metrics.md.",
	},
	{
		Name:          MetricChainInterceptsTotal,
		Definition:    "Dangerous-sequence interceptions fired by chain rules.",
		SourceEvent:   string(audit.EventToolChainDetected),
		SourceField:   "event_type",
		Computability: ComputableToday,
	},
	{
		Name:          MetricTaintBlocksTotal,
		Definition:    "Taint-triggered egress denials: the control recorded session taints. Narrow by construction — only the taint-egress branch populates session_taints today.",
		SourceEvent:   string(audit.EventToolDenied),
		SourceField:   "session_taints",
		Computability: ComputableToday,
		Gap:           "Open refinement: session-taint presence on every denial so the metric can widen to all tainted-session denials.",
	},
	{
		Name:          MetricUnloggedDenialsTotal,
		Definition:    "Declared terminal denials with no matching audit event. Mechanism only: most deny paths emit no request hash today, so production use stays a gap until they do.",
		SourceEvent:   "reconciliation of declared decisions vs tool_call_denied by request_hash",
		SourceField:   "request_hash",
		Computability: NeedsNewField,
		Gap:           "Emit request_hash on all terminal deny events; without join keys the metric cannot run on production logs.",
	},
}

// Report holds one computed number per metric plus the rule breakdown.
// Rule-less denials ride a separate counter, never an in-band sentinel:
// any sentinel string could collide with a legal egress-control name.
type Report struct {
	DeniedTotal     int64
	DeniedByRule    map[string]int64
	DeniedNoRule    int64
	ApprovalGates   int64
	ApprovalGrants  int64
	ChainIntercepts int64
	TaintBlocks     int64
	UnloggedDenials int64
	UnloggedDetail  []string
	// Unjoinable counts declared decisions that carry no request hash and
	// therefore can neither match nor miss: unprovable either way.
	Unjoinable int64
}

// DecisionRef declares one terminal decision the log must contain (test
// oracle / receipt excerpt for reconciliation).
type DecisionRef struct {
	RequestHash string
	Decision    string
}

// isJSONSpace reports JSONL framing whitespace only (space, tab, CR, LF).
// bytes.TrimSpace is deliberately not used: it also accepts vertical tab,
// form feed, NBSP, and other Unicode spaces, which would let corrupted
// lines pass as blank instead of failing closed.
func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func isBlankLine(line []byte) bool {
	for _, c := range line {
		if !isJSONSpace(c) {
			return false
		}
	}
	return true
}

// LoadEvents parses audit JSONL with newline framing as the parse
// primitive — one ReadBytes per record, no line-length cap (production
// records can exceed 1 MiB). Blank lines (JSON whitespace only) skip. A
// leftover without its framing newline is a torn tail and fails closed,
// matching the producer, which terminates every record with a newline.
func LoadEvents(r io.Reader) ([]audit.Event, error) {
	var events []audit.Event
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			if isBlankLine(line) {
				return events, nil
			}
			return nil, fmt.Errorf("truncated tail: final record lacks terminating newline")
		}
		if err != nil {
			return nil, err
		}
		if isBlankLine(line) {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("malformed record: %w", err)
		}
		if ev.EventType == "" {
			return nil, fmt.Errorf("record missing event_type")
		}
		events = append(events, ev)
	}
}

// Compute derives today's computable metrics from parsed events, in log
// order. Approval grants join holds on (request hash, session), consume one
// hold each, and additionally require the receipt to identify a human
// approve decision: capability accounting stores receipts in the same
// receipt-hash field on ordinary allows, and denied-after-hold emits no
// event at all, so hash-only matching would credit capability allows and
// stale holds. Terminal denials consume their hold: a decided hold can
// never grant later.
func Compute(events []audit.Event) Report {
	rep := Report{DeniedByRule: map[string]int64{}}
	holds := map[string]int{}
	holdKey := func(session, hash string) string { return hash + "\x00" + session }
	for _, ev := range events {
		switch ev.EventType {
		case audit.EventToolDenied:
			rep.DeniedTotal++
			if ev.PolicyRule == "" {
				rep.DeniedNoRule++
			} else {
				rep.DeniedByRule[ev.PolicyRule]++
			}
			if len(ev.SessionTaints) > 0 {
				rep.TaintBlocks++
			}
			if ev.RequestHash != "" {
				delete(holds, holdKey(ev.SessionID, ev.RequestHash))
			}
		case audit.EventToolAllowed:
			if ev.ApprovalReceiptHash != "" && ev.RequestHash != "" && isHumanApproveReceipt(ev.ApprovalReceipt) {
				if key := holdKey(ev.SessionID, ev.RequestHash); holds[key] > 0 {
					holds[key]--
					rep.ApprovalGrants++
				}
			}
		case audit.EventToolApprovalRequired:
			if ev.RequestHash != "" {
				holds[holdKey(ev.SessionID, ev.RequestHash)]++
			}
			rep.ApprovalGates++
		case audit.EventToolChainDetected:
			rep.ChainIntercepts++
		}
	}
	return rep
}

// isHumanApproveReceipt reports whether an attached receipt map identifies
// a human approval grant. Capability eval/pause receipts share the
// receipt-hash field but carry no approver identity and never decide
// "approve", so they can neither match nor mint grants.
func isHumanApproveReceipt(rec map[string]any) bool {
	if rec == nil {
		return false
	}
	approver, _ := rec["approver_id"].(string)
	decision, _ := rec["decision"].(string)
	return approver != "" && decision == "approve"
}

// Reconcile verifies every declared terminal deny decision has a matching
// tool_call_denied audit event by request hash. Only denials index: holds
// share hashes with their eventual denials, so other event types must not
// satisfy the lookup. Decision refs without a hash are unjoinable, never
// silently counted either way. A deny with no event is the negative case.
func Reconcile(rep Report, decisions []DecisionRef, events []audit.Event) Report {
	// Multiplicity matters: identical replayed requests share a hash, so
	// each declared decision consumes one logged occurrence.
	byHash := map[string]int{}
	for _, ev := range events {
		if ev.EventType != audit.EventToolDenied {
			continue
		}
		if ev.RequestHash == "" {
			continue
		}
		byHash[ev.RequestHash]++
	}
	for _, d := range decisions {
		if d.Decision != "deny" {
			continue
		}
		if d.RequestHash == "" {
			rep.Unjoinable++
			continue
		}
		if byHash[d.RequestHash] == 0 {
			rep.UnloggedDenials++
			rep.UnloggedDetail = append(rep.UnloggedDetail, d.RequestHash)
			continue
		}
		byHash[d.RequestHash]--
	}
	sort.Strings(rep.UnloggedDetail)
	return rep
}
