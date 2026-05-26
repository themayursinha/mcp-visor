package policy_test

import (
	"encoding/json"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

func makeLargePolicy(numServers, toolsPerServer, rulesPerTool int) *policy.Policy {
	servers := make([]policy.Server, numServers)
	for i := 0; i < numServers; i++ {
		tools := make([]policy.ToolRule, toolsPerServer)
		for j := 0; j < toolsPerServer; j++ {
			rules := make([]policy.ArgRule, rulesPerTool)
			for k := 0; k < rulesPerTool; k++ {
				rules[k] = policy.ArgRule{
					Type:     "deny_path",
					Patterns: []string{"/etc/passwd", "/etc/shadow", "**/.env", "**/*.pem"},
				}
			}
			tools[j] = policy.ToolRule{
				Name:    string(rune('a'+j)) + "_tool",
				Allowed: true,
				Risk:    policy.RiskMedium,
				Rules:   rules,
			}
		}
		servers[i] = policy.Server{
			Name:    string(rune('A'+i)) + "_server",
			Allowed: true,
			Tools:   tools,
		}
	}
	return &policy.Policy{
		Version:       "1.0",
		DefaultAction: policy.ActionDeny,
		Servers:       servers,
	}
}

func benchToolCallReq(name, path string) mcp.ToolsCallRequest {
	args, _ := json.Marshal(map[string]string{"path": path})
	return mcp.ToolsCallRequest{Name: name, Arguments: args}
}

func BenchmarkPolicyEvaluateSingleRule(b *testing.B) {
	pol := makeLargePolicy(5, 5, 5)
	eng := policy.NewEngine(pol)
	req := benchToolCallReq("b_tool", "/etc/passwd")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Evaluate("B_server", req)
	}
}

func BenchmarkPolicyEvaluateAllowPath(b *testing.B) {
	pol := makeLargePolicy(5, 5, 5)
	for i := range pol.Servers[0].Tools[0].Rules {
		pol.Servers[0].Tools[0].Rules[i] = policy.ArgRule{
			Type:     "allow_path",
			Patterns: []string{"/home/**", "/tmp/**", "/var/log/**"},
		}
	}
	eng := policy.NewEngine(pol)
	req := benchToolCallReq("a_tool", "/tmp/test.txt")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Evaluate("A_server", req)
	}
}

func BenchmarkPolicyEvaluateCommandPattern(b *testing.B) {
	pol := makeLargePolicy(1, 1, 1)
	pol.Servers[0].Tools[0].Rules[0] = policy.ArgRule{
		Type:     "deny_command_pattern",
		Patterns: []string{"rm\\s+-rf\\s+/", "curl.*\\|.*bash"},
	}
	eng := policy.NewEngine(pol)
	args, _ := json.Marshal(map[string]string{"command": "ls -la /tmp/test"})
	req := mcp.ToolsCallRequest{Name: "a_tool", Arguments: args}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Evaluate("A_server", req)
	}
}

func BenchmarkPolicyEvaluateManyRules(b *testing.B) {
	pol := &policy.Policy{
		Version:       "1.0",
		DefaultAction: policy.ActionDeny,
		Servers: []policy.Server{{
			Name:    "big-server",
			Allowed: true,
			Tools: []policy.ToolRule{{
				Name:    "big_tool",
				Allowed: true,
				Risk:    policy.RiskMedium,
				Rules: []policy.ArgRule{
					{Type: "deny_path", Patterns: []string{"/etc/passwd", "/etc/shadow", "**/.env"}},
					{Type: "allow_path", Patterns: []string{"/home/**", "/tmp/**"}},
					{Type: "max_file_size", Bytes: 10485760},
					{Type: "max_rows", Rows: 10000},
				},
			}},
		}},
	}
	eng := policy.NewEngine(pol)
	req := benchToolCallReq("big_tool", "/home/user/test.txt")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Evaluate("big-server", req)
	}
}

func BenchmarkPolicyEvaluateIdentity(b *testing.B) {
	pol := &policy.Policy{
		Version:       "1.0",
		DefaultAction: policy.ActionDeny,
		Servers: []policy.Server{{
			Name:    "srv",
			Allowed: true,
			Tools:   []policy.ToolRule{{Name: "read", Allowed: true}},
		}},
		Identities: []policy.Identity{{
			Name:           "agent-007",
			AllowedServers: []string{"srv"},
			AllowedTools:   []string{"srv/read"},
		}},
	}
	eng := policy.NewEngine(pol)
	eng.SetClientID("agent-007")
	req := benchToolCallReq("read", "/tmp/test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Evaluate("srv", req)
	}
}

func BenchmarkPolicyEvaluateChainNoMatch(b *testing.B) {
	pol := &policy.Policy{
		Version:       "1.0",
		DefaultAction: policy.ActionDeny,
		Servers: []policy.Server{{
			Name:    "srv",
			Allowed: true,
			Tools: []policy.ToolRule{
				{Name: "read", Allowed: true},
				{Name: "send", Allowed: true},
			},
		}},
		ToolChains: []policy.ChainRule{{
			Name:        "exfil",
			Sources:     []policy.ChainMatch{{Server: "*", ToolPattern: "read"}},
			Sinks:       []policy.ChainMatch{{Server: "*", ToolPattern: "send"}},
			Action:      policy.ActionDeny,
			WithinCalls: 5,
		}},
	}
	eng := policy.NewEngine(pol)
	req := benchToolCallReq("send", "https://safe.com")
	prev := []string{"srv:list", "srv:list", "srv:list"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.EvaluateChain("srv", req, prev)
	}
}

func BenchmarkPolicyEvaluateChainMatch(b *testing.B) {
	pol := &policy.Policy{
		Version:       "1.0",
		DefaultAction: policy.ActionDeny,
		Servers: []policy.Server{{
			Name:    "srv",
			Allowed: true,
			Tools: []policy.ToolRule{
				{Name: "read", Allowed: true},
				{Name: "send", Allowed: true},
			},
		}},
		ToolChains: []policy.ChainRule{{
			Name:        "exfil",
			Sources:     []policy.ChainMatch{{Server: "*", ToolPattern: "read"}},
			Sinks:       []policy.ChainMatch{{Server: "*", ToolPattern: "send"}},
			Action:      policy.ActionDeny,
			WithinCalls: 5,
		}},
	}
	eng := policy.NewEngine(pol)
	req := benchToolCallReq("send", "https://evil.com")
	prev := []string{"srv:read", "srv:list"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.EvaluateChain("srv", req, prev)
	}
}

func BenchmarkPolicyRegistryLookup(b *testing.B) {
	pol := makeLargePolicy(50, 10, 1)
	reg := policy.NewRegistry(pol)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.Tool("B_server", "c_tool")
	}
}

func BenchmarkPolicyRegistryFindTool(b *testing.B) {
	pol := makeLargePolicy(50, 10, 1)
	reg := policy.NewRegistry(pol)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.FindTool("c_tool")
	}
}

func BenchmarkPolicyLoadFile(b *testing.B) {
	b.StopTimer()
	path := "../../examples/policies/demo-policy.yaml"
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := policy.LoadFile(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}
