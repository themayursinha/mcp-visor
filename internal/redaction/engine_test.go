package redaction_test

import (
	"encoding/json"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/policy"
	"github.com/themayursinha/mcp-visor/internal/redaction"
)

func TestRedactAPIKey(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"headers": map[string]any{
			"Authorization": "Bearer sk-proj-deadbeef1234567890abcdef123456",
		},
	}

	redacted, result := eng.RedactArgs(args)
	if !result.Redacted {
		t.Error("expected redaction for API key")
	}

	headers, ok := redacted["headers"].(map[string]any)
	if !ok {
		t.Fatal("headers not preserved")
	}
	auth, ok := headers["Authorization"].(string)
	if !ok {
		t.Fatal("auth header not preserved")
	}
	if auth == "Bearer sk-proj-deadbeef1234567890abcdef123456" {
		t.Error("API key should have been redacted")
	}
	t.Logf("redacted auth: %s", auth)
}

func TestRedactGitHubToken(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"token": "ghp_1234567890abcdef1234567890abcdef123456",
	}

	redacted, result := eng.RedactArgs(args)
	if !result.Redacted {
		t.Error("expected redaction for GitHub token")
	}
	if redacted["token"] == "ghp_1234567890abcdef1234567890abcdef123456" {
		t.Error("GitHub token should have been redacted")
	}
	t.Logf("redacted token: %v", redacted["token"])
}

func TestRedactJWT(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"cookie": "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.abc123def456",
	}

	redacted, result := eng.RedactArgs(args)
	if !result.Redacted {
		t.Error("expected redaction for JWT")
	}
	cookie, _ := redacted["cookie"].(string)
	if cookie == "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.abc123def456" {
		t.Error("JWT should have been redacted")
	}
	t.Logf("redacted cookie: %s", cookie)
}

func TestRedactConnectionString(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"database_url": "mongodb://admin:SuperSecret123@db.internal:27017/prod",
	}

	redacted, result := eng.RedactArgs(args)
	if !result.Redacted {
		t.Error("expected redaction for connection string")
	}
	dbURL, _ := redacted["database_url"].(string)
	if dbURL == "mongodb://admin:SuperSecret123@db.internal:27017/prod" {
		t.Error("connection string should have been redacted")
	}
	t.Logf("redacted db url: %s", dbURL)
}

func TestRedactInternalIP(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"host": "10.0.1.25",
	}

	redacted, result := eng.RedactArgs(args)
	if !result.Redacted {
		t.Error("expected redaction for internal IP")
	}
	host, _ := redacted["host"].(string)
	if host == "10.0.1.25" {
		t.Error("internal IP should have been redacted")
	}
	t.Logf("redacted host: %s", host)
}

func TestRedactPrivateKey(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"key": `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQ...
-----END RSA PRIVATE KEY-----`,
	}

	redacted, result := eng.RedactArgs(args)
	if !result.Redacted {
		t.Error("expected redaction for private key")
	}
	key, _ := redacted["key"].(string)
	if key == args["key"] {
		t.Error("private key should have been redacted")
	}
}

func TestNoRedactionForSafeData(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"path":    "/home/user/document.txt",
		"message": "Hello, world!",
		"count":   42,
	}

	_, result := eng.RedactArgs(args)
	if result.Redacted {
		t.Error("should not redact safe data")
	}
}

func TestRedactDeeplyNestedMap(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	args := map[string]any{
		"config": map[string]any{
			"database": map[string]any{
				"connection": "postgresql://user:password123@db.example.com:5432/mydb",
			},
		},
	}

	redacted, result := eng.RedactArgs(args)
	if !result.Redacted {
		t.Fatal("expected redaction for nested connection string")
	}

	config, _ := redacted["config"].(map[string]any)
	db, _ := config["database"].(map[string]any)
	conn, _ := db["connection"].(string)
	if conn == "postgresql://user:password123@db.example.com:5432/mydb" {
		t.Error("nested connection string should have been redacted")
	}
	t.Logf("redacted: %s", conn)
}

func TestRedactArgsJSON(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	raw := json.RawMessage(`{"Authorization":"Bearer sk-proj-deadbeef1234567890abcdef123456","url":"https://api.example.com"}`)

	redacted, result := eng.RedactArgsJSON(raw)
	if !result.Redacted {
		t.Error("expected redaction for API key in JSON")
	}

	var m map[string]any
	if err := json.Unmarshal(redacted, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	auth, _ := m["Authorization"].(string)
	if auth == "Bearer sk-proj-deadbeef1234567890abcdef123456" {
		t.Error("API key should have been redacted in JSON")
	}
}

func TestRedactOutput(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns:       policy.DefaultRedactionPatterns(),
		OutputPatterns: policy.DefaultOutputRedactionPatterns(),
	})

	output := "SELECT * FROM users; Found credentials: password=SuperSecret123"

	redacted := eng.RedactOutput(output)
	t.Logf("redacted output: %s", redacted)

	if redacted == output {
		t.Error("output should have been redacted")
	}
}

func TestRedactOutputWithSecretsPattern(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		OutputPatterns: []policy.RedactionPattern{
			{Name: "secret", Regex: `(password|secret|token)\s*[:=]\s*["']?([^"'\s]+)["']?`, Replacement: "$1=[REDACTED]"},
		},
	})

	tests := []struct {
		input    string
		contains string
	}{
		{"password=SuperSecret123", "password=[REDACTED]"},
		{"token: abc123", "token=[REDACTED]"},
		{"secret = \"mykey\"", "secret=[REDACTED]"},
	}

	for _, tt := range tests {
		result := eng.RedactOutput(tt.input)
		if result == tt.input {
			t.Errorf("input %q was not redacted", tt.input)
		}
		t.Logf("%q → %q", tt.input, result)
	}
}

func TestIsSensitiveFile(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		SensitiveFiles: []string{
			"**/.env",
			"**/.env.*",
			"**/credentials",
			"**/*.pem",
			"**/*.key",
			"**/.ssh/**",
		},
	})

	tests := []struct {
		path      string
		sensitive bool
	}{
		{"/home/user/.env", true},
		{"/project/.env.production", true},
		{"/app/credentials", true},
		{"/etc/ssl/private/key.pem", true},
		{"/home/user/.ssh/id_rsa", true},
		{"/home/user/document.txt", false},
		{"/usr/local/etc/config.yaml", false},
		{"/tmp/test.json", false},
	}

	for _, tt := range tests {
		result := eng.IsSensitiveFile(tt.path)
		if result != tt.sensitive {
			t.Errorf("IsSensitiveFile(%q) = %v, expected %v", tt.path, result, tt.sensitive)
		}
	}
}

func TestRedactOutputKeepsNonSecrets(t *testing.T) {
	eng := redaction.NewEngine(policy.RedactionConfig{
		Patterns: policy.DefaultRedactionPatterns(),
	})

	output := "The file contains 42 lines and no secrets"
	result := eng.RedactOutput(output)
	if result != output {
		t.Errorf("safe output was modified: %q → %q", output, result)
	}
}
