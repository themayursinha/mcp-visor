package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveArtifactsCleansPartialPrepare(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sess := &demoSession{
		mockBin:     filepath.Join(dir, "mcp-mock"),
		visorBin:    filepath.Join(dir, "mcp-visor"),
		policyPath:  filepath.Join(dir, "policy.yaml"),
		auditLog:    filepath.Join(dir, "audit.jsonl"),
		observeLog:  filepath.Join(dir, "obs.jsonl"),
		approvalDir: filepath.Join(dir, "approvals"),
	}
	for _, p := range []string{sess.mockBin, sess.visorBin, sess.policyPath, sess.auditLog, sess.observeLog} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(sess.approvalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sess.cleanup = sess.removeArtifacts
	sess.cleanup()
	for _, p := range []string{sess.mockBin, sess.visorBin, sess.policyPath, sess.auditLog, sess.observeLog, sess.approvalDir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("artifact left behind: %s (%v)", p, err)
		}
	}
}
