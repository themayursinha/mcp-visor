package transport

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestPipeTransport(t *testing.T) {
	r1, w1 := NewPipePair()
	r2, w2 := NewPipePair()

	client := NewPipeTransport(r1, w2)
	server := NewPipeTransport(r2, w1)

	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"}}`)

	if err := client.EncodeRaw(msg); err != nil {
		t.Fatalf("client EncodeRaw: %v", err)
	}

	received, err := server.ReadRaw()
	if err != nil {
		t.Fatalf("server ReadRaw: %v", err)
	}

	if string(received) != string(msg) {
		t.Errorf("message mismatch: got %s, want %s", string(received), string(msg))
	}
}

func TestPipeTransportBidirectional(t *testing.T) {
	r1, w1 := NewPipePair()
	r2, w2 := NewPipePair()

	client := NewPipeTransport(r1, w2)
	server := NewPipeTransport(r2, w1)

	req := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	resp := json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{}}`)

	if err := client.EncodeRaw(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	if _, err := server.ReadRaw(); err != nil {
		t.Fatalf("read: %v", err)
	}

	if err := server.EncodeRaw(resp); err != nil {
		t.Fatalf("encode response: %v", err)
	}

	received, err := client.ReadRaw()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if string(received) != string(resp) {
		t.Errorf("response mismatch")
	}
}

func TestMockTransport(t *testing.T) {
	mock := NewMockTransport()
	defer mock.Close()

	go func() {
		msg := <-mock.Receive()
		mock.Send(msg)
	}()

	req := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if err := mock.EncodeRaw(req); err != nil {
		t.Fatalf("EncodeRaw: %v", err)
	}

	resp, err := mock.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	if string(resp) != string(req) {
		t.Errorf("expected echo, got %s", string(resp))
	}
}

func NewPipePair() (*channelReader, *channelWriter) {
	ch := make(chan byte, 4096)
	return &channelReader{ch: ch}, &channelWriter{ch: ch}
}

type channelReader struct {
	ch  chan byte
	buf []byte
}

func (r *channelReader) Read(b []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(b, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	for i := 0; i < len(b); i++ {
		v, ok := <-r.ch
		if !ok {
			if i > 0 {
				return i, nil
			}
			return 0, nil
		}
		b[i] = v
		if v == '\n' {
			return i + 1, nil
		}
	}
	return len(b), nil
}

func (r *channelReader) Close() error {
	return nil
}

type channelWriter struct {
	ch chan byte
}

func (w *channelWriter) Write(b []byte) (int, error) {
	for _, c := range b {
		w.ch <- c
	}
	return len(b), nil
}

func (w *channelWriter) Close() error {
	close(w.ch)
	return nil
}

func TestTLSConfigEmpty(t *testing.T) {
	tc, err := buildTLSConfig(nil)
	if err != nil {
		t.Fatalf("buildTLSConfig(nil): %v", err)
	}
	if tc != nil {
		t.Error("nil config should return nil TLS config")
	}
}

func TestTLSConfigInsecure(t *testing.T) {
	cfg := &TLSConfig{
		InsecureSkip: true,
	}
	tc, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !tc.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestTLSConfigRejectsIncompleteClientKeyPair(t *testing.T) {
	cases := []struct {
		name string
		cfg  *TLSConfig
	}{
		{name: "cert_only", cfg: &TLSConfig{CertFile: "/tmp/client.crt"}},
		{name: "key_only", cfg: &TLSConfig{KeyFile: "/tmp/client.key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildTLSConfig(tc.cfg); err == nil {
				t.Fatal("expected incomplete client cert/key pair to fail closed")
			}
		})
	}
}

func TestHTTPTransportAllowsConcurrentReadAndWrite(t *testing.T) {
	// Reproduce the deadlock class: a blocked ReadRaw must not prevent EncodeRaw.
	pr, pw := io.Pipe()
	ht := &HTTPTransport{
		url:        "http://127.0.0.1:9",
		client:     &http.Client{Timeout: 50 * time.Millisecond},
		sseReader:  pr,
		sseScanner: bufio.NewScanner(pr),
	}
	ht.sseScanner.Split(scanSSEEvent)

	started := make(chan struct{})
	doneRead := make(chan error, 1)
	go func() {
		close(started)
		_, err := ht.ReadRaw()
		doneRead <- err
	}()
	<-started
	time.Sleep(30 * time.Millisecond) // ensure ReadRaw is waiting on SSE

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- ht.EncodeRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	}()

	select {
	case err := <-writeDone:
		// EncodeRaw should complete (network failure is fine) without waiting for ReadRaw.
		if err == nil {
			t.Fatal("expected EncodeRaw network error against closed endpoint, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EncodeRaw blocked while ReadRaw held shared lock (deadlock class)")
	}

	_ = pw.Close()
	select {
	case <-doneRead:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadRaw did not exit after SSE close")
	}
}

func TestMockTransportServeMCP(t *testing.T) {
	mock := NewMockTransport()
	defer mock.Close()

	handler := mock.ServeMCP()

	go func() {
		req := <-mock.Receive()
		mock.Send(json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		_ = req
	}()

	var w testResponseWriter
	r := &http.Request{
		Body: &testReadCloser{data: `{"jsonrpc":"2.0","id":1,"method":"ping"}`},
	}

	handler(&w, r)

	var resp map[string]any
	if err := json.Unmarshal(w.body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["result"] == nil {
		t.Error("expected result in response")
	}
}

type testResponseWriter struct {
	header     http.Header
	body       []byte
	statusCode int
}

func (w *testResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *testResponseWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return len(data), nil
}

func (w *testResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

type testReadCloser struct {
	data string
	pos  int
}

func (r *testReadCloser) Read(b []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *testReadCloser) Close() error {
	return nil
}
