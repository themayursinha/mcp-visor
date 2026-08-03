//go:build !interop

package main_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/demoutil"
)

func TestDemoRunnerExitSuccess(t *testing.T) {
	cmd := exec.Command("go", "run", "../../examples/demo-runner")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("demo-runner failed: %v\n%s", err, out)
	}
	output := string(out)

	require(t, output, "1  ALLOW")
	require(t, output, "file_read /home/user/readme.md")
	require(t, output, "2  ALLOW + TAINT")
	require(t, output, "taint=sensitive_file_accessed")
	require(t, output, "3  DENY")
	require(t, output, "rule=block_sensitive_egress")
	require(t, output, "source_tool=file_read")
	require(t, output, "sink_tool=http_post")
	require(t, output, "decision=deny")
	require(t, output, "Model proposed.")
	require(t, output, "Proxy enforced.")

	if strings.Contains(output, "sk-") && !strings.Contains(output, "redacted") {
		t.Error("output may contain secret-like content")
	}
}

func TestValidateObservations(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if err := demoutil.ValidateObservations(nil); err == nil {
			t.Error("expected error for empty observations")
		}
	})
	t.Run("missing read 100", func(t *testing.T) {
		obs := []demoutil.ObsLine{
			{Tool: "file_read", RequestID: 200, Received: true},
		}
		if err := demoutil.ValidateObservations(obs); err == nil {
			t.Error("expected error for missing file_read #100")
		}
	})
	t.Run("missing read 200", func(t *testing.T) {
		obs := []demoutil.ObsLine{
			{Tool: "file_read", RequestID: 100, Received: true},
		}
		if err := demoutil.ValidateObservations(obs); err == nil {
			t.Error("expected error for missing file_read #200")
		}
	})
	t.Run("http_post 300 received", func(t *testing.T) {
		obs := []demoutil.ObsLine{
			{Tool: "file_read", RequestID: 100, Received: true},
			{Tool: "file_read", RequestID: 200, Received: true},
			{Tool: "http_post", RequestID: 300, Received: true},
		}
		if err := demoutil.ValidateObservations(obs); err == nil {
			t.Error("expected error when http_post #300 received by server")
		}
	})
	t.Run("valid", func(t *testing.T) {
		obs := []demoutil.ObsLine{
			{Tool: "file_read", RequestID: 100, Received: true},
			{Tool: "file_read", RequestID: 200, Received: true},
		}
		if err := demoutil.ValidateObservations(obs); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidateEvidence(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if err := demoutil.ValidateEvidence(&demoutil.DemoEvidence{}); err == nil {
			t.Error("expected error for empty evidence")
		}
	})
	t.Run("missing taint", func(t *testing.T) {
		ev := &demoutil.DemoEvidence{SourceTool: "file_read", SinkTool: "http_post", Rule: "block", Decision: "deny"}
		if err := demoutil.ValidateEvidence(ev); err == nil {
			t.Error("expected error for missing taint")
		}
	})
	t.Run("wrong decision", func(t *testing.T) {
		ev := &demoutil.DemoEvidence{Taint: "t", SourceTool: "f", SinkTool: "h", Rule: "r", Decision: "allow"}
		if err := demoutil.ValidateEvidence(ev); err == nil {
			t.Error("expected error for wrong decision")
		}
	})
	t.Run("valid", func(t *testing.T) {
		ev := &demoutil.DemoEvidence{
			Taint: "sensitive_file_accessed", SourceTool: "file_read",
			SinkTool: "http_post", Rule: "block_sensitive_egress", Decision: "deny",
		}
		if err := demoutil.ValidateEvidence(ev); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func require(t *testing.T, output, substr string) {
	t.Helper()
	if !strings.Contains(output, substr) {
		t.Errorf("missing required output: %q", substr)
	}
}
