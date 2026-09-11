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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	// MetricApprovalGatesTotal counts calls held for human approval.
	MetricApprovalGatesTotal = "brake.approval_gates_total"
	// MetricApprovalOverridesTotal counts approvals overridden after hold.
	// NOT COMPUTABLE TODAY: no approval-outcome event exists.
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
		Definition:    "Denials grouped by the firing policy rule name.",
		SourceEvent:   string(audit.EventToolDenied),
		SourceField:   "policy_rule",
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
		Name:          MetricApprovalOverridesTotal,
		Definition:    "Held calls later overridden (approved despite hold, or hold bypassed).",
		SourceEvent:   "(no approval-outcome event exists)",
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
		Definition:    "Denials on sessions already carrying taint.",
		SourceEvent:   string(audit.EventToolDenied),
		SourceField:   "session_taints",
		Computability: ComputableToday,
	},
	{
		Name:          MetricUnloggedDenialsTotal,
		Definition:    "Declared terminal decisions with no matching audit event.",
		SourceEvent:   "reconciliation of declared decisions vs tool_call_denied by request_hash",
		SourceField:   "request_hash",
		Computability: ComputableToday,
	},
}

// Report holds one computed number per metric plus the rule breakdown.
type Report struct {
	DeniedTotal     int64
	DeniedByRule    map[string]int64
	ApprovalGates   int64
	ChainIntercepts int64
	TaintBlocks     int64
	UnloggedDenials int64
	UnloggedDetail  []string
}

// DecisionRef declares one terminal decision the log must contain (test
// oracle / receipt excerpt for reconciliation).
type DecisionRef struct {
	RequestHash string
	Decision    string
}

// LoadEvents parses audit JSONL (one audit.Event per line, blank lines
// skipped). Unknown trailing structure fails closed.
func LoadEvents(r io.Reader) ([]audit.Event, error) {
	var events []audit.Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if ev.EventType == "" {
			return nil, fmt.Errorf("line %d: missing event_type", line)
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// Compute derives today's computable metrics from parsed events.
func Compute(events []audit.Event) Report {
	rep := Report{DeniedByRule: map[string]int64{}}
	for _, ev := range events {
		switch ev.EventType {
		case audit.EventToolDenied:
			rep.DeniedTotal++
			rule := ev.PolicyRule
			if rule == "" {
				rule = ev.Reason
			}
			if rule == "" {
				rule = "unspecified"
			}
			rep.DeniedByRule[rule]++
			if len(ev.SessionTaints) > 0 {
				rep.TaintBlocks++
			}
		case audit.EventToolApprovalRequired:
			rep.ApprovalGates++
		case audit.EventToolChainDetected:
			rep.ChainIntercepts++
		}
	}
	return rep
}

// Reconcile verifies every declared terminal deny decision has a matching
// audit event by request hash. A deny with no event is the negative case:
// the brake fired (or should have) with no record. Returns the report with
// UnloggedDenials filled; error only on malformed input.
func Reconcile(rep Report, decisions []DecisionRef, events []audit.Event) Report {
	byHash := map[string]bool{}
	for _, ev := range events {
		if ev.RequestHash == "" {
			continue
		}
		// Normalize: match on raw or hex sha256 of the reference.
		byHash[ev.RequestHash] = true
		sum := sha256.Sum256([]byte(ev.RequestHash))
		byHash[hex.EncodeToString(sum[:])] = true
	}
	for _, d := range decisions {
		if d.Decision != "deny" {
			continue
		}
		if d.RequestHash == "" || !byHash[d.RequestHash] {
			rep.UnloggedDenials++
			rep.UnloggedDetail = append(rep.UnloggedDetail, d.RequestHash)
		}
	}
	sort.Strings(rep.UnloggedDetail)
	return rep
}
