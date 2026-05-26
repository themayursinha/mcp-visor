package redaction_test

import (
	"encoding/json"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/redaction"
)

func benchRedactionCfg() policy.RedactionConfig {
	return policy.RedactionConfig{
		Patterns: []policy.RedactionPattern{
			{Name: "api_key_openai", Regex: `sk-[a-zA-Z0-9]{32,}`, Replacement: "[OPENAI_KEY]"},
			{Name: "github_token", Regex: `ghp_[a-zA-Z0-9]{24,}`, Replacement: "[GITHUB_TOKEN]"},
			{Name: "aws_key", Regex: `AKIA[0-9A-Z]{16}`, Replacement: "[AWS_KEY]"},
			{Name: "jwt", Regex: `eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`, Replacement: "[JWT]"},
			{Name: "password", Regex: `(?i)(password|passwd|pwd)['":]\s*['"]?([^'"]+)`, Replacement: "$1=[REDACTED]"},
		},
		OutputPatterns: []policy.RedactionPattern{
			{Name: "output_secret", Regex: `secret[=:]\s*\S+`, Replacement: "secret=[REDACTED]"},
		},
		SensitiveFiles: []string{
			"/etc/passwd",
			"**/.env",
			"**/*.pem",
		},
	}
}

func BenchmarkRedactArgsFlatWithSecrets(b *testing.B) {
	eng := redaction.NewEngine(benchRedactionCfg())
	args := map[string]any{
		"api_key": "sk-abc123def456ghi789jkl012mno345pqr",
		"token":   "ghp_abcdefghijklmnopqrstuvwxyz12",
		"command": "ls -la",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.RedactArgs(args)
	}
}

func BenchmarkRedactArgsNoSecrets(b *testing.B) {
	eng := redaction.NewEngine(benchRedactionCfg())
	args := map[string]any{
		"path":    "/tmp/test.txt",
		"command": "ls -la",
		"verbose": "true",
		"count":   "42",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.RedactArgs(args)
	}
}

func BenchmarkRedactArgsDeepNested(b *testing.B) {
	eng := redaction.NewEngine(benchRedactionCfg())
	args := map[string]any{
		"level0": map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"level3": map[string]any{
						"api_key": "sk-deep-nested-secret-key-here-abcdef1234567890",
					},
				},
			},
		},
		"other": "clean value",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.RedactArgs(args)
	}
}

func BenchmarkRedactArgsJSON(b *testing.B) {
	eng := redaction.NewEngine(benchRedactionCfg())
	raw, _ := json.Marshal(map[string]any{
		"path":    "/tmp/test",
		"api_key": "sk-abc123def456ghi789jkl012mno345",
		"nested": map[string]any{
			"token": "ghp_abcdefghijklmnopqrstuvwxyz12",
		},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.RedactArgsJSON(raw)
	}
}

func BenchmarkRedactOutput(b *testing.B) {
	eng := redaction.NewEngine(benchRedactionCfg())
	output := "File read successfully. API response: secret=abc123def456. Everything OK."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.RedactOutput(output)
	}
}

func BenchmarkIsSensitiveFile(b *testing.B) {
	eng := redaction.NewEngine(benchRedactionCfg())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.IsSensitiveFile("/home/user/.env")
	}
}
