package actorcontext

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func fixtureContext() Context {
	return Context{
		Version:            VersionV1,
		PrincipalID:        "user1",
		ActingAgent:        "coding-agent",
		Transaction:        "txn-1",
		ActorChain:         []ActorRef{{ID: "user1"}, {ID: "planner"}, {ID: "coding-agent"}},
		Scopes:             []string{"read", "write"},
		Issuer:             "https://sts.example.test",
		Audience:           "https://visor-gateway.example.test",
		TokenID:            "jti-1",
		ExpiresAt:          time.Date(2026, 5, 21, 13, 0, 0, 0, time.UTC),
		ProofKeyThumbprint: "abc",
		VerificationMethod: VerificationSTSDpop,
	}
}

func TestSealAndDecodeRoundTrip(t *testing.T) {
	c := fixtureContext()
	raw, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.IdentitySnapshotHash == "" || got.PrincipalID != "user1" || got.ActingAgent != "coding-agent" {
		t.Fatalf("%+v", got)
	}
	if err := got.Check(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckExpired(t *testing.T) {
	c := fixtureContext()
	if err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(c.ExpiresAt); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateActingAgentLastHop(t *testing.T) {
	c := fixtureContext()
	c.ActingAgent = "orphan-agent"
	if err := c.Seal(); err == nil {
		t.Fatal("expected last-hop mismatch")
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	c := fixtureContext()
	raw, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	injected := []byte(strings.TrimSuffix(string(raw), "}") + `,"extra":true}`)
	if _, err := Decode(bytes.NewReader(injected)); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestDecodeRejectsOversized(t *testing.T) {
	if _, err := Decode(bytes.NewReader(bytes.Repeat([]byte("a"), maxBytes+1))); err == nil {
		t.Fatal("expected oversized rejection")
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	c := fixtureContext()
	raw, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(bytes.NewReader(append(append([]byte{}, raw...), []byte(`{"x":1}`)...))); err == nil {
		t.Fatal("expected trailing JSON rejection")
	}
	if _, err := Decode(bytes.NewReader(append(append([]byte{}, raw...), '\n'))); err != nil {
		t.Fatalf("trailing newline must be allowed: %v", err)
	}
}

func TestDecodeFDPipe(t *testing.T) {
	c := fixtureContext()
	raw, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got, err := DecodeFD(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Transaction != "txn-1" {
		t.Fatalf("%+v", got)
	}
}

func TestDecodeFDUnset(t *testing.T) {
	got, err := DecodeFD(0)
	if err != nil || got != nil {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestStripArgumentIdentity(t *testing.T) {
	args := map[string]any{"path": "/tmp/a", "_verified_actor": map[string]any{"principal_id": "spoof"}}
	got, changed := StripArgumentIdentity(args)
	if !changed || got["path"] != "/tmp/a" {
		t.Fatalf("%v changed=%v", got, changed)
	}
	if _, ok := got["_verified_actor"]; ok {
		t.Fatal("spoof key must be stripped")
	}
}

func TestHasScope(t *testing.T) {
	c := fixtureContext()
	if !c.HasScope("write") || c.HasScope("admin") {
		t.Fatal(c.Scopes)
	}
}
