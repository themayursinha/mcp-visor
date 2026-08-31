package policy

import "testing"

func TestRejectDuplicateJSONKeys(t *testing.T) {
	if err := rejectDuplicateJSONKeys(nil); err != nil {
		t.Fatalf("empty arguments must pass: %v", err)
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"recipient":"finance@example.com"}`)); err != nil {
		t.Fatalf("unique keys must pass: %v", err)
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"recipient":"attacker@example.com","recipient":"finance@example.com"}`)); err == nil {
		t.Fatal("duplicate top-level key must fail")
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"a":{"b":1,"b":2}}`)); err == nil {
		t.Fatal("nested duplicate key must fail")
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"msg":"say \"recipient\": x"}`)); err != nil {
		t.Fatalf("quoted text that is not a key must pass: %v", err)
	}
}
