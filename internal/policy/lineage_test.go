package policy_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/mcp-visor/internal/lineage"
	"github.com/themayursinha/mcp-visor/internal/lineage/testfixture"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

// Frozen a807ff6 json.Marshal(policy) of the identity-less github/write_file fixture.
const legacyPolicyJSON = `{"Version":"1.0","Description":"","DefaultAction":"deny","Settings":{"MaxArgumentSizeBytes":1048576,"MaxOutputSizeBytes":10485760,"SessionMaxTools":100,"SessionTimeoutSecs":3600,"ApprovalTimeoutSecs":300,"MaxSpawnDepth":0,"ChainWindowSize":10,"LogLevel":"info","CapabilityEval":false,"InstructionAuthorityContinuity":false,"InstructionAuthorityEd25519PublicKeys":null},"Servers":[{"Name":"github","Transport":"","Allowed":true,"AllowedDestinations":null,"DeniedDestinations":null,"WorkspaceRoot":"","Attestation":null,"Tools":[{"Name":"write_file","Allowed":true,"Risk":"high","ApprovalRequired":false,"Delegates":false,"Rules":null}]}],"ToolChains":null,"Taints":null,"EgressControls":null,"Identities":null,"TimeRestrictions":null,"Redaction":{"Patterns":[{"Name":"openai_api_key","Regex":"sk-[a-zA-Z0-9_-]{20,}","Replacement":"[REDACTED: OpenAI API Key]"},{"Name":"github_token","Regex":"ghp_[a-zA-Z0-9]{36}","Replacement":"[REDACTED: GitHub Token]"},{"Name":"slack_token","Regex":"xox[baprs]-[a-zA-Z0-9-]+","Replacement":"[REDACTED: Slack Token]"},{"Name":"aws_key","Regex":"AKIA[0-9A-Z]{16}","Replacement":"[REDACTED: AWS Access Key]"},{"Name":"jwt_token","Regex":"eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+","Replacement":"[REDACTED: JWT]"},{"Name":"private_key","Regex":"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----","Replacement":"[REDACTED: Private Key]"},{"Name":"connection_string","Regex":"(mongodb|postgresql|mysql|redis|jdbc)://[^:]+:[^@]+@[^\\s]+","Replacement":"[REDACTED: Connection String]"},{"Name":"internal_ip","Regex":"(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})","Replacement":"[REDACTED: Internal IP]"}],"OutputRedaction":true,"OutputPatterns":[{"Name":"secrets_in_output","Regex":"(password|secret|token|key|credential)\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?","Replacement":"$1=[REDACTED]"}],"SensitiveFiles":["**/.env","**/.env.*","**/credentials","**/secrets","**/.aws/credentials","**/.ssh/**","**/.docker/config.json","**/kubeconfig","**/.npmrc","**/*.pem","**/*.key"]},"CapabilityOwnership":null}`

// Frozen SHA-256 of the approval evidence marshal path (json.Marshal of the loaded policy).
const legacyPolicyHash = "4dec525f6b269bf6e10f6f27da22b6eb5ac0d7ddc84237db0982c216af93543d"

const legacyYAML = `
version: "1.0"
default_action: deny
servers:
  - name: github
    allowed: true
    tools:
      - name: write_file
        allowed: true
        risk: high
`

func TestLineageLegacyPolicyJSONAndApprovalHashUnchanged(t *testing.T) {
	p, err := policy.Load([]byte(legacyYAML))
	if err != nil {
		t.Fatalf("identity-less policy must load: %v", err)
	}
	got, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(legacyPolicyJSON)) {
		t.Fatalf("legacy json.Marshal bytes changed\ngot  %s\nwant %s", got, legacyPolicyJSON)
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != legacyPolicyHash {
		t.Fatalf("legacy approval policy hash changed: got %s want %s", hex.EncodeToString(sum[:]), legacyPolicyHash)
	}
	if bytes.Contains(got, []byte(`"Identity"`)) || bytes.Contains(got, []byte(`"Trajectories"`)) {
		t.Fatal("Identity and Trajectories must be absent, not null or empty")
	}
	eng := policy.NewEngine(p)
	eng.SetClientID("orphan-1")
	d := eng.Evaluate("github", mcp.ToolsCallRequest{Name: "write_file", Arguments: mustJSON(testfixture.Args())})
	if d.Action != policy.ActionAllow {
		t.Fatalf("identity-less policy must not lineage-gate, got %s: %s", d.Action, d.Reason)
	}
	if d.Lineage != nil {
		t.Fatalf("identity-less events must omit lineage, got %+v", d.Lineage)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func loadLin(t *testing.T, client string) *policy.Engine {
	t.Helper()
	p, err := policy.Load([]byte(testfixture.PolicyYAML()))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(p)
	eng.SetClientID(client)
	return eng
}

func evalLin(eng *policy.Engine, args map[string]any) policy.Decision {
	return eng.Evaluate(testfixture.Server, mcp.ToolsCallRequest{Name: testfixture.Tool, Arguments: mustJSON(args)})
}

func TestLineageValidMultiAgentAllowed(t *testing.T) {
	got := evalLin(loadLin(t, testfixture.Coding), testfixture.Args())
	if got.Action != policy.ActionAllow {
		t.Fatalf("valid chain must allow, got %s: %s", got.Action, got.Reason)
	}
	if got.Lineage == nil || got.Lineage.HumanPrincipalID != testfixture.Human {
		t.Fatalf("allow evidence: %+v", got.Lineage)
	}
}

func TestLineageEvaluateDenies(t *testing.T) {
	cases := []struct {
		client, reason string
		mut            func(map[string]any)
	}{
		{"orphan-1", "lineage:unregistered-principal", nil},
		{"mcp-client", "lineage:unregistered-principal", nil},
		{testfixture.Coding, "lineage:delegation-ceiling-violation", func(a map[string]any) { a["_lineage"].(map[string]any)["grant_id"] = "grant-forged" }},
		{testfixture.Coding, "lineage:trajectory-mismatch", func(a map[string]any) { a["_lineage"].(map[string]any)["trajectory_id"] = "" }},
		{testfixture.Coding, "lineage:delegation-ceiling-violation", func(a map[string]any) { a["_lineage"].(map[string]any)["capability"] = testfixture.CapRead }},
		{testfixture.Coding, "lineage:delegation-ceiling-violation", func(a map[string]any) {
			a["_lineage"] = "not-an-object"
		}},
		{testfixture.Coding, "lineage:delegation-ceiling-violation", func(a map[string]any) {
			a["_lineage"].(map[string]any)["grant_id"] = 1
		}},
	}
	for _, tc := range cases {
		args := testfixture.Args()
		if tc.mut != nil {
			tc.mut(args)
		}
		got := evalLin(loadLin(t, tc.client), args)
		if got.Action != policy.ActionDeny || got.Reason != tc.reason {
			t.Fatalf("client=%s want %s, got %s %s", tc.client, tc.reason, got.Action, got.Reason)
		}
	}
}

func TestLineageMalformedSectionFailsClosed(t *testing.T) {
	y := testfixture.PolicyYAML()
	cases := []string{
		strings.Replace(y, "version: 1", "version: 2", 1),
		strings.Replace(y, "expiry: \""+testfixture.Expiry+"\"", "expiry: \"not-a-time\"", 1),
		strings.Replace(y, "parent_grant_id: "+testfixture.GrantPlanner, "parent_grant_id: missing", 1),
	}
	for _, yaml := range cases {
		if _, err := policy.Load([]byte(yaml)); err == nil {
			t.Fatal("malformed lineage must fail Load")
		}
	}
}

func TestLineageUngatedToolNotChecked(t *testing.T) {
	p, err := policy.Load([]byte(testfixture.PolicyYAML() + "      - {name: read_file, allowed: true, risk: low}\n"))
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(p)
	eng.SetClientID("orphan-1")
	got := eng.Evaluate("github", mcp.ToolsCallRequest{Name: "read_file", Arguments: mustJSON(map[string]any{"path": "x"})})
	if got.Action != policy.ActionAllow {
		t.Fatalf("ungated tool must allow, got %s", got.Action)
	}
}

func TestLineageTrajectoryInconsistentAtLoad(t *testing.T) {
	y := strings.Replace(testfixture.PolicyYAML(), "capability: github.repo.write", "capability: github.repo.admin", 1)
	if _, err := policy.Load([]byte(y)); err == nil {
		t.Fatal("trajectory capability not on grant chain must fail load")
	}
}

func TestLineageEvaluateLineageAtUsesCallerTime(t *testing.T) {
	eng := loadLin(t, testfixture.Coding)
	now, err := time.Parse(time.RFC3339, testfixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := time.Parse(time.RFC3339, testfixture.Expiry)
	if err != nil {
		t.Fatal(err)
	}
	args := testfixture.Args()
	got := eng.EvaluateLineageAt(testfixture.Server, testfixture.Tool, args, eng.Policy(), now)
	if got.Action != policy.ActionAllow {
		t.Fatalf("in-window snapshot must allow, got %s: %s", got.Action, got.Reason)
	}
	got = eng.EvaluateLineageAt(testfixture.Server, testfixture.Tool, args, eng.Policy(), exp)
	if got.Action != policy.ActionDeny || got.Reason != lineage.ReasonUnregisteredPrincipal {
		t.Fatalf("expired snapshot must deny R1, got %s: %s", got.Action, got.Reason)
	}
}
