package transport

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
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
