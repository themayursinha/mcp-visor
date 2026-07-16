package policy

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestWatcherHooksRunBeforePolicyPublish(t *testing.T) {
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

	var sawNewDuringHook atomic.Bool
	w.OnReload(func(pol *Policy) {
		// During the hook, Current() must still expose the previous policy.
		cur, _ := w.Current()
		if cur.DefaultAction != ActionDeny {
			sawNewDuringHook.Store(true)
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

	if sawNewDuringHook.Load() {
		t.Fatal("Current() published new policy before hooks finished")
	}
	cur, _ := w.Current()
	if cur.DefaultAction != ActionAllow {
		t.Fatalf("after reload Current should be allow, got %s", cur.DefaultAction)
	}
}
