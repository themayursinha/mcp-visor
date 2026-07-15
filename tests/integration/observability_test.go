package main_test

import (
	"bytes"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestServeWithPrometheusMetrics(t *testing.T) {
	visor := buildVisor(t)
	mock := buildMockServer(t)
	policy := writePermissivePolicy(t, mock)

	cmd := exec.Command(visor, "serve",
		"-server", mock,
		"-policy", policy,
		"-metrics-addr", "127.0.0.1:19381",
		"-log-level", "error",
	)
	var stderr bytes.Buffer
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	deadline := time.Now().Add(3 * time.Second)
	var ready bool
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:19381/metrics")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), "mcp_visor_messages_processed_total") {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("metrics endpoint not ready; stderr: %s", stderr.String())
	}

	// Default path: observability enabled but no traffic yet — counters should exist at 0.
	resp, err := http.Get("http://127.0.0.1:19381/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "mcp_visor_messages_processed_total 0") {
		t.Fatalf("expected zero processed counter, got: %s", body)
	}
}
