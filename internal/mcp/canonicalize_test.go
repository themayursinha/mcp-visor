package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalizeJSONLineCollapsesDuplicateMembers(t *testing.T) {
	in := []byte(`{"recipient":"attacker@example.com","recipient":"finance@example.com"}` + "\n")
	out, err := CanonicalizeJSONLine(in)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Fatal("stdio newline must be preserved")
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &got); err != nil {
		t.Fatalf("canonical JSON: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one unique key, got %#v", got)
	}
	if got["recipient"] != "finance@example.com" {
		t.Fatalf("last-wins unique object, got %#v", got)
	}
	if strings.Contains(string(out), "attacker@example.com") {
		t.Fatalf("first-wins attacker must not remain in canonical bytes: %s", out)
	}
}

func TestCanonicalizeJSONLineCollapsesEscapedEquivalentKeys(t *testing.T) {
	in := []byte(`{"recipient":"attacker@example.com","\u0072ecipient":"finance@example.com"}`)
	out, err := CanonicalizeJSONLine(in)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("canonical JSON: %v", err)
	}
	if got["recipient"] != "finance@example.com" {
		t.Fatalf("escaped-equivalent keys must collapse last-wins, got %#v", got)
	}
	if strings.Contains(string(out), "attacker@example.com") {
		t.Fatalf("discarded attacker must not remain: %s", out)
	}
	if strings.Contains(string(out), `\u0072`) {
		t.Fatalf("canonical keys must be decoded spellings, got %s", out)
	}
}

func TestCanonicalizeJSONLineCollapsesDuplicateNestedObjects(t *testing.T) {
	in := []byte(`{"name":"send_email","arguments":{"recipient":"attacker@example.com"},"arguments":{"recipient":"finance@example.com"}}`)
	out, err := CanonicalizeJSONLine(in)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("canonical JSON: %v", err)
	}
	args, ok := got["arguments"].(map[string]any)
	if !ok {
		t.Fatalf("arguments must be a unique object, got %#v", got)
	}
	if args["recipient"] != "finance@example.com" {
		t.Fatalf("duplicate arguments members must last-wins, got %#v", args)
	}
	if strings.Contains(string(out), "attacker@example.com") {
		t.Fatalf("first arguments object must not remain: %s", out)
	}
}

func TestCanonicalizeJSONLineRejectsTrailingData(t *testing.T) {
	if _, err := CanonicalizeJSONLine([]byte(`{"a":1}{"b":2}`)); err == nil {
		t.Fatal("trailing JSON must fail closed")
	}
	if _, err := CanonicalizeJSONLine(nil); err == nil {
		t.Fatal("empty JSON must fail closed")
	}
}
