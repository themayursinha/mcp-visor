package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const thirdPartyEffectPolicy = `
version: "1.0"
description: "Book a class for alice; do not cancel anyone else's reservation"
default_action: deny
servers:
  - name: "booking"
    allowed: true
    tools:
      - name: "create_reservation"
        allowed: true
        risk: high
        rules:
          - type: allow_resource_owner
            patterns:
              - "alice"
      - name: "cancel_reservation"
        allowed: true
        risk: high
        rules:
          - type: allow_resource_owner
            patterns:
              - "alice"
`

func loadOwnerEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(thirdPartyEffectPolicy))
	if err != nil {
		t.Fatalf("load owner policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalBooking(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("booking", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func assertCrossPrincipalEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"cross-principal effect",
		"argument class PRINCIPAL",
		"effect class THIRD_PARTY",
		"authority transition USER->OTHER",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestResourceOwnerMandateInstantiationAllowed(t *testing.T) {
	eng := loadOwnerEngine(t)

	got := evalBooking(eng, "create_reservation", map[string]any{
		"owner":    "alice",
		"class_id": "spin-0700",
		"slot":     "2026-09-02T07:00:00Z",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("alice booking herself must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalBooking(eng, "cancel_reservation", map[string]any{
		"owner":          "Alice",
		"reservation_id": "res-alice-1",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("alice cancelling her own reservation must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalBooking(eng, "cancel_reservation", map[string]any{
		"userId":         " alice ",
		"reservation_id": "res-alice-1",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("userId alias of mandated principal must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestResourceOwnerCrossPrincipalDenied(t *testing.T) {
	eng := loadOwnerEngine(t)

	got := evalBooking(eng, "cancel_reservation", map[string]any{
		"owner":          "bob",
		"reservation_id": "res-918",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("cancelling bob must deny, got %s: %s", got.Action, got.Reason)
	}
	assertCrossPrincipalEvidence(t, got.Reason)

	got = evalBooking(eng, "create_reservation", map[string]any{
		"owner":    "bob",
		"class_id": "spin-0700",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("creating for bob must deny, got %s: %s", got.Action, got.Reason)
	}
}

func TestResourceOwnerEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadOwnerEngine(t)
	got := evalBooking(eng, "cancel_reservation", map[string]any{
		"owner":   "alice",
		"user_id": "bob",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("shadow owner alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertCrossPrincipalEvidence(t, got.Reason)
}

func TestResourceOwnerMissingFailsClosed(t *testing.T) {
	eng := loadOwnerEngine(t)
	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "missing", args: map[string]any{"reservation_id": "res-1"}},
		{name: "blank", args: map[string]any{"owner": "   "}},
		{name: "non-string", args: map[string]any{"owner": 918}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalBooking(eng, "cancel_reservation", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("missing/blank/non-string owner must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "resource owner is required") {
				t.Fatalf("want resource owner is required, got %s", got.Reason)
			}
		})
	}
}

func TestResourceOwnerEmptyAllowlistFailsClosed(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "booking"
    allowed: true
    tools:
      - name: "cancel_reservation"
        allowed: true
        rules:
          - type: allow_resource_owner
            patterns: ["   "]
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalBooking(eng, "cancel_reservation", map[string]any{"owner": "alice"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("empty allowlist must deny, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "resource owner allowlist is empty") {
		t.Fatalf("want empty allowlist reason, got %s", got.Reason)
	}
}

func TestAllowedToolWithoutOwnerRuleDoesNotBoundPrincipal(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "booking"
    allowed: true
    tools:
      - name: "cancel_reservation"
        allowed: true
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalBooking(eng, "cancel_reservation", map[string]any{"owner": "bob"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: tool allow without owner rule still allows bob, got %s: %s", got.Action, got.Reason)
	}
}
