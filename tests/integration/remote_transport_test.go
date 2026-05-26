package main_test

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

func TestRemoteTransportHandshake(t *testing.T) {
	receivedInit := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		<-receivedInit

		resp := `data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"mock-remote","version":"1.0"},"capabilities":{"tools":{"listChanged":true}}}}

`
		fmt.Fprint(w, resp)
		flusher.Flush()

		select {}
	})
	mux.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedInit <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	t.Logf("mock remote server listening on %s", addr)

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })

	visor := buildVisor(t)

	cmd := exec.Command(visor, "serve",
		"-server-url", fmt.Sprintf("http://%s", addr),
		"-server-name", "mock-remote",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	r := bufio.NewReader(stdout)
	w := bufio.NewWriter(stdin)

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			t.Logf("visor stderr: %s", scanner.Text())
		}
	}()

	time.Sleep(500 * time.Millisecond)

	initMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0"},
		},
	}
	_ = sendMessage(w, initMsg)

	resp, err := readMessage(r)
	if err != nil {
		t.Fatalf("read init response: %v", err)
	}
	if resp["result"] == nil {
		t.Fatal("expected result in init response")
	}
	result := resp["result"].(map[string]any)
	si := result["serverInfo"].(map[string]any)
	if si["name"] != "mock-remote" {
		t.Errorf("expected mock-remote server, got %v", si["name"])
	}
	t.Logf("remote handshake succeeded: server=%s", si["name"])

	initializedMsg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	_ = sendMessage(w, initializedMsg)
	t.Log("sent initialized notification")
}

func TestRemoteTransportBadURL(t *testing.T) {
	visor := buildVisor(t)

	cmd := exec.Command(visor, "serve", "-server-url", "http://127.0.0.1:19999", "-server-name", "bad-server")
	stdout, _ := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start visor: %v", err)
	}

	go func() { bufio.NewReader(stdout) }()
	scanner := bufio.NewScanner(stderr)
	found := false
	for scanner.Scan() {
		t.Logf("visor stderr: %s", scanner.Text())
		if containsText(scanner.Text(), "connect SSE") || containsText(scanner.Text(), "connection refused") {
			found = true
		}
	}
	if found {
		t.Log("correctly detected connection failure")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func containsText(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
