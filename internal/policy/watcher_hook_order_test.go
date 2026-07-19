package policy

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestWatcherHooksRunAfterPolicyPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	initial := `
version: "1.0"
default_action: deny
servers:
  - name: "fs"
    allowed: true
    tools:
      - name: "read_file"
        allowed: false
`
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	var sawPublishedPolicyDuringHook atomic.Bool
	w.OnReload(func(pol *Policy) {
		// Observers run after publication and receive the same policy snapshot.
		cur, _ := w.Current()
		if cur == pol && cur.DefaultAction == ActionAllow {
			sawPublishedPolicyDuringHook.Store(true)
		}
		if pol.DefaultAction != ActionAllow {
			t.Errorf("hook should receive the new policy document")
		}
	})

	updated := `
version: "1.0"
default_action: allow
servers:
  - name: "fs"
    allowed: true
    tools:
      - name: "read_file"
        allowed: true
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()

	if !sawPublishedPolicyDuringHook.Load() {
		t.Fatal("Current() did not publish the new policy before observers ran")
	}
	cur, _ := w.Current()
	if cur.DefaultAction != ActionAllow {
		t.Fatalf("after reload Current should be allow, got %s", cur.DefaultAction)
	}
}
