package observability

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

func loadBrakeFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "brake-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestContractNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Contract {
		if m.Name == "" {
			t.Fatal("contract has an unnamed metric")
		}
		if seen[m.Name] {
			t.Fatalf("duplicate metric name %q", m.Name)
		}
		seen[m.Name] = true
		if m.Computability == NeedsNewField && m.Gap == "" {
			t.Fatalf("metric %q needs a field but names no gap", m.Name)
		}
	}
}

func TestComputeFixture(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Compute(events)
	if rep.DeniedTotal != 3 {
		t.Fatalf("denied=%d want 3", rep.DeniedTotal)
	}
	wantRules := map[string]int64{"block_sensitive_egress": 1, "allow_destination": 1}
	if !reflect.DeepEqual(rep.DeniedByRule, wantRules) {
		t.Fatalf("by_rule=%v want %v", rep.DeniedByRule, wantRules)
	}
	if rep.DeniedNoRule != 1 {
		t.Fatalf("denied_no_rule=%d want 1 (separate counter, no sentinel)", rep.DeniedNoRule)
	}
	// Every computed counter has a registered contract name.
	names := map[string]bool{}
	for _, m := range Contract {
		names[m.Name] = true
	}
	for _, want := range []string{MetricDeniedTotal, MetricDeniedByRule, MetricDeniedNoRule, MetricApprovalGatesTotal, MetricApprovalGrantsTotal, MetricApprovalOverridesTotal, MetricChainInterceptsTotal, MetricTaintBlocksTotal, MetricUnloggedDenialsTotal} {
		if !names[want] {
			t.Fatalf("counter %q missing from Contract", want)
		}
	}
	if rep.ApprovalGates != 1 {
		t.Fatalf("gates=%d want 1", rep.ApprovalGates)
	}
	if rep.ApprovalGrants != 1 {
		t.Fatalf("grants=%d want 1 (capability-accounted allow must not count)", rep.ApprovalGrants)
	}
	if rep.ChainIntercepts != 1 {
		t.Fatalf("chains=%d want 1", rep.ChainIntercepts)
	}
	if rep.TaintBlocks != 1 {
		t.Fatalf("taint_blocks=%d want 1", rep.TaintBlocks)
	}
}

func TestReconcileClean(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-deny-1", SessionID: "sess-brake-001", Decision: "deny"},
		{RequestHash: "req-deny-2", SessionID: "sess-brake-001", Decision: "deny"},
		{RequestHash: "req-allow-1", SessionID: "sess-brake-001", Decision: "allow"},
		{RequestHash: "", SessionID: "sess-brake-001", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 0 {
		t.Fatalf("unlogged=%d (%v) want 0", rep.UnloggedDenials, rep.UnloggedDetail)
	}
	if rep.Unjoinable != 1 {
		t.Fatalf("unjoinable=%d want 1 (hashless runtime-limits deny)", rep.Unjoinable)
	}
}

// TestReconcileCatchesMissingEvent is the negative case: a deny happened
// (declared) but no event was emitted. The gap must be caught, not silent.
func TestReconcileCatchesMissingEvent(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-deny-1", SessionID: "sess-brake-001", Decision: "deny"},
		{RequestHash: "req-vanished-9", SessionID: "sess-brake-001", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 1 {
		t.Fatalf("unlogged=%d want 1", rep.UnloggedDenials)
	}
	if len(rep.UnloggedDetail) != 1 || !strings.Contains(rep.UnloggedDetail[0], "req-vanished-9") {
		t.Fatalf("detail names the gap: %v", rep.UnloggedDetail)
	}
}

// TestHoldDoesNotSatisfyDenial: the approval hold shares req-hold-1 with the
// granted call, but no tool_call_denied carries it. Holds must never satisfy
// a denial lookup.
func TestHoldDoesNotSatisfyDenial(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-hold-1", SessionID: "sess-brake-001", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 1 {
		t.Fatalf("unlogged=%d want 1 (hold must not satisfy denial)", rep.UnloggedDenials)
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	if _, err := LoadEvents(bytes.NewReader([]byte("{oops\n"))); err == nil {
		t.Fatal("malformed line accepted")
	}
	if _, err := LoadEvents(bytes.NewReader([]byte("{\"timestamp\":\"x\"}\n"))); err == nil {
		t.Fatal("event without type accepted")
	}
}

func TestLoadLargeLine(t *testing.T) {
	// Production records can exceed 1 MiB (argument limit + envelope):
	// parsing must not cap line length.
	big := `{"timestamp":"2026-09-11T08:00:00Z","event_type":"session_started","session_id":"` + strings.Repeat("s", 2*1024*1024) + `","agent_id":"a","policy_decision":"allow"}` + "\n"
	events, err := LoadEvents(bytes.NewReader([]byte(big)))
	if err != nil {
		t.Fatalf("large line rejected: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
}

func TestReconcileConsumesMultiplicity(t *testing.T) {
	// Two declared denials, one logged occurrence (replay): the second is unlogged.
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-deny-1", SessionID: "sess-brake-001", Decision: "deny"},
		{RequestHash: "req-deny-1", SessionID: "sess-brake-001", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 1 {
		t.Fatalf("unlogged=%d want 1 (replay multiplicity)", rep.UnloggedDenials)
	}
}

func TestTruncatedTailRejected(t *testing.T) {
	data := loadBrakeFixture(t)
	// Strip the final newline: last record is now a torn tail.
	torn := bytes.TrimRight(data, "\n")
	if bytes.Equal(torn, data) {
		t.Skip("fixture has no trailing newline; rewrite surgery")
	}
	if _, err := LoadEvents(bytes.NewReader(torn)); err == nil {
		t.Fatal("torn tail accepted")
	}
	if _, err := LoadEvents(bytes.NewReader(data)); err != nil {
		t.Fatalf("clean fixture rejected: %v", err)
	}
}

func TestTrailingBlankSpaceAccepted(t *testing.T) {
	data := loadBrakeFixture(t)
	padded := append(append([]byte{}, data...), []byte("\n  \n")...)
	events, err := LoadEvents(bytes.NewReader(padded))
	if err != nil {
		t.Fatalf("trailing blank space rejected: %v", err)
	}
	if len(events) != 12 {
		t.Fatalf("events=%d want 12", len(events))
	}
}

func TestEmptyInputAccepted(t *testing.T) {
	events, err := LoadEvents(bytes.NewReader([]byte("  \n")))
	if err != nil {
		t.Fatalf("blank input rejected: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events=%d want 0", len(events))
	}
}

func TestMissingDelimiterRejected(t *testing.T) {
	data := loadBrakeFixture(t)
	// Remove one inter-record newline: two valid objects joined as }{.
	joined := bytes.Replace(data, []byte("}\n{"), []byte("}{"), 1)
	if bytes.Equal(joined, data) {
		t.Skip("fixture shape changed; rewrite surgery")
	}
	if _, err := LoadEvents(bytes.NewReader(joined)); err == nil {
		t.Fatal("missing newline delimiter accepted")
	}
	if _, err := LoadEvents(bytes.NewReader(data)); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
}

func TestLongTrailingBlankSpaceAccepted(t *testing.T) {
	data := loadBrakeFixture(t)
	padded := append(append([]byte{}, data...), bytes.Repeat([]byte(" \t"), 5000)...)
	padded = append(padded, '\n')
	events, err := LoadEvents(bytes.NewReader(padded))
	if err != nil {
		t.Fatalf("long trailing blank space rejected: %v", err)
	}
	if len(events) != 12 {
		t.Fatalf("events=%d want 12", len(events))
	}
}

func TestNonJSONWhitespaceNotBlank(t *testing.T) {
	// Vertical tab / form feed are not JSONL framing whitespace: a
	// corrupted line must fail closed, not skip.
	for _, raw := range []string{"\v\n", "\f\n", "{\"a\":1}\n\v\n"} {
		if _, err := LoadEvents(bytes.NewReader([]byte(raw))); err == nil {
			t.Fatalf("non-JSON whitespace accepted: %q", raw)
		}
	}
	// True framing whitespace stays legal.
	if _, err := LoadEvents(bytes.NewReader([]byte(" \t\r\n"))); err != nil {
		t.Fatalf("framing whitespace rejected: %v", err)
	}
}

// testEvent builds synthetic audit events for join-semantics tests.
type testEvent struct {
	kind        string // hold | deny | allow
	hash        string
	session     string
	receiptHash string
	receipt     map[string]any
}

func testEvents(tes []testEvent) []audit.Event {
	out := make([]audit.Event, 0, len(tes))
	for _, te := range tes {
		ev := audit.Event{SessionID: te.session, RequestHash: te.hash}
		switch te.kind {
		case "hold":
			ev.EventType = audit.EventToolApprovalRequired
		case "deny":
			ev.EventType = audit.EventToolDenied
			ev.Decision = "deny"
		case "allow":
			ev.EventType = audit.EventToolAllowed
			ev.Decision = "allow"
			ev.ApprovalReceiptHash = te.receiptHash
			ev.ApprovalReceipt = te.receipt
		}
		out = append(out, ev)
	}
	return out
}

// TestStaleHoldGrantsNothing reproduces the exact review scenario: a hold
// denied off-record (denied-after-hold emits no event), then a retry as an
// ordinary capability-accounted allow with the same hash in the same
// session. No human receipt exists, so no grant may count.
func TestStaleHoldGrantsNothing(t *testing.T) {
	events := []testEvent{
		{kind: "hold", hash: "req-h", session: "s"},
		{kind: "allow", hash: "req-h", session: "s", receiptHash: "receipt-sha256:cap", receipt: map[string]any{"receipt_version": 1, "decision": "ALLOW"}},
	}
	rep := Compute(testEvents(events))
	if rep.ApprovalGrants != 0 {
		t.Fatalf("grants=%d want 0 (capability allow on stale hold)", rep.ApprovalGrants)
	}
}

// TestDenyConsumesHold: an explicit deny retires the hold, so even a later
// human-receipt allow with the same hash cannot count.
func TestDenyConsumesHold(t *testing.T) {
	events := []testEvent{
		{kind: "hold", hash: "req-h", session: "s"},
		{kind: "deny", hash: "req-h", session: "s"},
		{kind: "allow", hash: "req-h", session: "s", receiptHash: "receipt-sha256:grant", receipt: map[string]any{"decision": "approve", "approver_id": "human-operator"}},
	}
	rep := Compute(testEvents(events))
	if rep.ApprovalGrants != 0 {
		t.Fatalf("grants=%d want 0 (deny consumed the hold)", rep.ApprovalGrants)
	}
}

func TestCrossSessionSubstitutionRejected(t *testing.T) {
	// Same raw request (same hash) in two sessions: the logged denial in
	// sess-brake-001 must not satisfy a declaration from sess-other.
	events, err := LoadEvents(bytes.NewReader(loadBrakeFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(Report{}, []DecisionRef{
		{RequestHash: "req-deny-1", SessionID: "sess-other", Decision: "deny"},
	}, events)
	if rep.UnloggedDenials != 1 {
		t.Fatalf("unlogged=%d want 1 (cross-session substitution)", rep.UnloggedDenials)
	}
}

func TestDenyConsumesOneHold(t *testing.T) {
	// Two overlapping holds, one terminal deny, one human grant: the deny
	// retires exactly its own hold; the grant still counts.
	grant := map[string]any{"decision": "approve", "approver_id": "human-operator"}
	events := testEvents([]testEvent{
		{kind: "hold", hash: "req-h", session: "s"},
		{kind: "hold", hash: "req-h", session: "s"},
		{kind: "deny", hash: "req-h", session: "s"},
		{kind: "allow", hash: "req-h", session: "s", receiptHash: "receipt-sha256:g", receipt: grant},
	})
	rep := Compute(events)
	if rep.ApprovalGrants != 1 {
		t.Fatalf("grants=%d want 1 (deny must consume exactly one hold)", rep.ApprovalGrants)
	}
}

func TestDocContractTableMatches(t *testing.T) {
	// Contract/code/doc drift guard: parse the contract table in
	// docs/brake-metrics.md and require one row per normative metric whose
	// source, event, and status columns match the Contract entry. Row
	// deletion, renamed metrics, or diverged sources/events/status fail
	// here — not in review.
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "brake-metrics.md"))
	if err != nil {
		t.Fatal(err)
	}
	rows := parseContractTable(t, string(doc))
	for _, m := range Contract {
		row, ok := rows[m.Name]
		if !ok {
			t.Fatalf("contract table has no row for %q", m.Name)
		}
		for _, token := range strings.Split(m.SourceField, "+") {
			token = strings.ReplaceAll(token, "`", "")
			token = strings.ReplaceAll(token, "(", "")
			token = strings.ReplaceAll(token, ")", "")
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			// Boundary match on backtick-stripped text (spaces kept, so
			// word boundaries survive): not_policy_rule must not satisfy
			// policy_rule.
			pat := `\b` + regexp.QuoteMeta(token) + `\b`
			matched, err := regexp.MatchString(pat, fieldNorm(row.source))
			if err != nil || !matched {
				t.Fatalf("row %q omits source vocabulary %q", m.Name, strings.TrimSpace(token))
			}
		}
		// Event identity is exact-set equality over event tokens: substring
		// matching lets negated or extended identifiers
		// (not_tool_call_denied) pass.
		if want, got := eventTokenSet(m.SourceEvent), eventTokenSet(row.event); !reflect.DeepEqual(want, got) {
			t.Fatalf("row %q events %v do not match contract %v", m.Name, got, want)
		}
		wantStatus := map[Computability]string{ComputableToday: "computabletoday", NeedsNewField: "needsnewfield"}[m.Computability]
		if !strings.Contains(normalizeToken(row.status), wantStatus) {
			t.Fatalf("row %q status %q does not match contract %q", m.Name, row.status, m.Computability)
		}
		if m.SourceField == "" {
			t.Fatalf("contract entry %q has no source field", m.Name)
		}
	}
}

type contractRow struct {
	source string
	event  string
	status string
}

// parseContractTable extracts metric-name → row columns from the
// "## Contract table" markdown section.
func parseContractTable(t *testing.T, doc string) map[string]contractRow {
	t.Helper()
	rows := map[string]contractRow{}
	inTable := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "## ") {
			inTable = strings.HasPrefix(line, "## Contract table")
			continue
		}
		if !inTable || !strings.HasPrefix(line, "| `") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			t.Fatalf("malformed contract row: %q", line)
		}
		name := normalizeToken(parts[1])
		rows[name] = contractRow{source: parts[3], event: parts[3], status: parts[5]}
	}
	return rows
}

func normalizeToken(s string) string {
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// fieldNorm strips code fencing but keeps spacing so word boundaries in
// field-vocabulary matching survive.
func fieldNorm(s string) string {
	return strings.ReplaceAll(s, "`", "")
}

// eventTokenSet extracts the event identity of a source description: the
// audit event vocabulary members it names, plus "none" for explicitly
// event-less sources. Fields that merely share a prefix shape
// (session_taints) are not events and never match.
func eventTokenSet(s string) map[string]bool {
	set := map[string]bool{}
	// Spaces preserved (fieldNorm): fusing prose around event names would
	// hide them from \b matching and make both sets vacuously equal.
	for _, w := range wordRe.FindAllString(fieldNorm(s), -1) {
		if auditEventUniverse[w] {
			set[w] = true
		}
	}
	if strings.Contains(s, "none:") {
		set["none"] = true
	}
	return set
}

// auditEventUniverse is every audit event type a contract may name.
var auditEventUniverse = map[string]bool{
	string(audit.EventToolAllowed):          true,
	string(audit.EventToolDenied):           true,
	string(audit.EventToolApprovalRequired): true,
	string(audit.EventToolChainDetected):    true,
	string(audit.EventSessionTainted):       true,
	string(audit.EventSessionStarted):       true,
	string(audit.EventSessionEnded):         true,
	string(audit.EventPolicyLoaded):         true,
	string(audit.EventPolicyReloaded):       true,
}

var wordRe = regexp.MustCompile(`\b[a-z][a-z0-9_]*\b`)
