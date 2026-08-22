package proxy

import (
	"net/netip"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/capability"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

// TestStringArgsPreservesArgvArray (P2-1): an argv array under a command-bearing
// key must be preserved as a space-joined string so the capability signal
// extractor can see the shell invocation. Dropping it is fail-open: an
// args-derived host_exec signal would never be extracted.
func TestStringArgsPreservesArgvArray(t *testing.T) {
	args := map[string]any{"command": "bash", "args": []any{"bash", "-c", "id"}}
	got := stringArgs(args)
	if got["args"] != "bash -c id" {
		t.Fatalf("P2-1 RED: argv array not preserved; got args=%q (want \"bash -c id\")", got["args"])
	}
	if got["command"] != "bash" {
		t.Fatalf("command scalar dropped: %q", got["command"])
	}
}

// TestStringArgsPreservesStringSlice (P2-1): a []string slit must also be
// flattened deterministically.
func TestStringArgsPreservesStringSlice(t *testing.T) {
	args := map[string]any{"args": []string{"/bin/sh", "-c", "echo hi"}}
	got := stringArgs(args)
	if got["args"] != "/bin/sh -c echo hi" {
		t.Fatalf("P2-1 RED: []string slice not preserved; got %q", got["args"])
	}
}

// TestStringArgsDropsNonStringScalar (P2-1): a number/boolean must not be
// forged into a command token.
func TestStringArgsDropsNonStringScalar(t *testing.T) {
	args := map[string]any{"path": "/tmp/f", "count": 42, "enabled": true}
	got := stringArgs(args)
	if _, ok := got["count"]; ok {
		t.Fatalf("number leaked into typed args: %v", got)
	}
	if _, ok := got["enabled"]; ok {
		t.Fatalf("bool leaked into typed args: %v", got)
	}
	if got["path"] != "/tmp/f" {
		t.Fatalf("string path dropped: %q", got["path"])
	}
}

// TestDestHostFromArgsHostname (P2-2): a hostname in a url/host arg must be
// extracted as a structured DestHost so a non-canonical net tool emits an
// egress destination rather than falling through with no signal.
func TestDestHostFromArgsHostname(t *testing.T) {
	got := destHostFromArgs("web_fetch", map[string]any{"url": "https://api.example.com/v1"})
	if got != "api.example.com" {
		t.Fatalf("P2-2 RED: hostname not extracted; got %q (want api.example.com)", got)
	}
	got = destHostFromArgs("web_fetch", map[string]any{"host": "Example.COM"})
	if got != "example.com" {
		t.Fatalf("host not lowercased/stripped; got %q", got)
	}
}

// TestDestHostFromArgsIPLiteral (P2-2): an IP literal must NOT be returned as a
// hostname; the IP path owns it.
func TestDestHostFromArgsIPLiteral(t *testing.T) {
	got := destHostFromArgs("web_fetch", map[string]any{"url": "https://10.0.0.1/path"})
	if got != "" {
		t.Fatalf("IP literal leaked into DestHost: %q", got)
	}
}

// TestCapabilityDeclaredAuthorityNoGetwdFallback (P2-6): a server with no
// declared WorkspaceRoot must NOT fall back to the process cwd; it leaves the
// root empty so the evaluator fails closed on a missing workspace root.
func TestCapabilityDeclaredAuthorityNoGetwdFallback(t *testing.T) {
	pol := &policy.Policy{
		Version:       "1.0",
		DefaultAction: policy.ActionAllow,
		Servers: []policy.Server{
			{Name: "workspace", Allowed: true},
		},
	}
	da := capabilityDeclaredAuthority(pol, "workspace")
	if da.WorkspaceRoot != "" {
		t.Fatalf("P2-6 RED: WorkspaceRoot forged (got %q); want empty so evaluator fails closed", da.WorkspaceRoot)
	}
}

// TestDestHostFromArgsEmpty (P2-2): no hostname arg -> empty, no invention.
func TestDestHostFromArgsEmpty(t *testing.T) {
	if got := destHostFromArgs("web_fetch", map[string]any{"path": "/tmp/x"}); got != "" {
		t.Fatalf("invented a target: %q", got)
	}
}

// TestDestIPStillWorks ensures the IP path is untouched.
func TestDestIPStillWorks(t *testing.T) {
	addr := destIPFromArgs("web_fetch", map[string]any{"url": "https://10.1.2.3:8080/x"})
	if addr != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("destIPFromArgs changed: %v", addr)
	}
}

// TestDestHostIgnoresPayloadURLOnGenericTool: Rev 15 / Codex P2 — url/host
// on exec/write_file is payload, not a destination. dest_host remains a
// schema-confirmed destination on any tool.
func TestDestHostIgnoresPayloadURLOnGenericTool(t *testing.T) {
	if got := destHostFromArgs("exec", map[string]any{"url": "https://example.com"}); got != "" {
		t.Fatalf("exec({url}) must not populate DestHost, got %q", got)
	}
	if got := destIPFromArgs("exec", map[string]any{"url": "https://10.1.2.3/x"}); got.IsValid() {
		t.Fatalf("exec({url}) must not populate DestIP, got %v", got)
	}
	if got := destHostFromArgs("exec", map[string]any{"dest_host": "example.com"}); got != "example.com" {
		t.Fatalf("explicit dest_host must still populate on a generic tool, got %q", got)
	}
}

func TestPathArgIgnoredOnGenericTool(t *testing.T) {
	if got := pathArgFromRedacted("get_metadata", map[string]any{"path": "/docs"}); got != "" {
		t.Fatalf("get_metadata({path}) must not populate Step.Path, got %q", got)
	}
	if got := pathArgFromRedacted("exec", map[string]any{"file": "/etc/passwd"}); got != "" {
		t.Fatalf("exec({file}) must not populate Step.Path, got %q", got)
	}
}

func TestPathArgPopulatedOnFileTool(t *testing.T) {
	if got := pathArgFromRedacted("file_write", map[string]any{"path": "/tmp/out.txt"}); got != "/tmp/out.txt" {
		t.Fatalf("file_write({path}) must populate Step.Path, got %q", got)
	}
	if got := pathArgFromRedacted("write_file", map[string]any{"file_path": "/tmp/a"}); got != "/tmp/a" {
		t.Fatalf("write_file({file_path}) must populate Step.Path, got %q", got)
	}
	if got := pathArgFromRedacted("read_file", map[string]any{"file": "/tmp/b"}); got != "/tmp/b" {
		t.Fatalf("read_file({file}) must populate Step.Path, got %q", got)
	}
}

// TestStringArgsFlattensNestedCommandBearingObject: a command buried in a
// nested object under a command-bearing key must remain visible. Dropping
// the object is fail-open (run({"arguments":{"command":"bash -c id"}}) → ALLOW).
func TestStringArgsFlattensNestedCommandBearingObject(t *testing.T) {
	got := stringArgs(map[string]any{
		"arguments": map[string]any{"command": "bash -c id"},
	})
	if got["arguments"] != "bash -c id" {
		t.Fatalf("nested command-bearing object dropped; got %#v", got)
	}
}

// TestStringArgsFlattensArrayOfCommandObjects: a command-bearing array of
// objects is the same surface as a nested object. Dropping map elements
// is fail-open (run({"arguments":[{"command":"bash -c id"}]}) → ALLOW).
func TestStringArgsFlattensArrayOfCommandObjects(t *testing.T) {
	got := stringArgs(map[string]any{
		"arguments": []any{map[string]any{"command": "bash -c id"}},
	})
	if got["arguments"] != "bash -c id" {
		t.Fatalf("array of command objects dropped; got %#v", got)
	}
}

// TestStringArgsDropsPayloadArrayOfObjects: a payload-key array of objects
// is not command surface (Rev 15).
func TestStringArgsDropsPayloadArrayOfObjects(t *testing.T) {
	got := stringArgs(map[string]any{
		"content": []any{map[string]any{"command": "bash -c id"}},
	})
	if _, ok := got["content"]; ok {
		t.Fatalf("payload array of objects leaked into typed args: %#v", got)
	}
}

// TestStringArgsFlattensDoublyNestedCommandBearing: a command two maps deep
// under arguments is still command surface.
func TestStringArgsFlattensDoublyNestedCommandBearing(t *testing.T) {
	got := stringArgs(map[string]any{
		"arguments": map[string]any{
			"nested": map[string]any{"command": "bash -c id"},
		},
	})
	if got["arguments"] != "bash -c id" {
		t.Fatalf("doubly nested command dropped; got %#v", got)
	}
}

// TestStringArgsDropsNestedNonCommandObject: Rev 15 false-positive control —
// a nested object under a payload key is not command surface.
func TestStringArgsDropsNestedNonCommandObject(t *testing.T) {
	got := stringArgs(map[string]any{
		"content": map[string]any{"command": "bash -c id"},
	})
	if _, ok := got["content"]; ok {
		t.Fatalf("non-command nested object leaked into typed args: %#v", got)
	}
}

var _ = capability.ErrInvalidStep
