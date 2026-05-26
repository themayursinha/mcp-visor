package transport

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type HTTPTransport struct {
	url        string
	client     *http.Client
	sseURL     string
	sseReader  io.ReadCloser
	sseScanner *bufio.Scanner
	mu         sync.Mutex
	reqID      int64
}

type HTTPConfig struct {
	BaseURL     string
	SSEPath     string
	Timeout     time.Duration
	TLS         *TLSConfig
	Headers     map[string]string
}

type TLSConfig struct {
	CertFile       string
	KeyFile        string
	CAFile         string
	InsecureSkip   bool
	ServerName     string
}

func NewHTTPTransport(cfg HTTPConfig) (*HTTPTransport, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.SSEPath == "" {
		cfg.SSEPath = "/sse"
	}

	tlsConfig, err := buildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("tls config: %w", err)
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	baseURL := strings.TrimRight(cfg.BaseURL, "/")

	return &HTTPTransport{
		url:    baseURL,
		client: client,
		sseURL: baseURL + cfg.SSEPath,
	}, nil
}

func buildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	tc := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkip,
		ServerName:         cfg.ServerName,
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert/key: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tc.RootCAs = caCertPool
	}

	return tc, nil
}

func (t *HTTPTransport) ConnectSSE() error {
	req, err := http.NewRequest(http.MethodGet, t.sseURL, nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect SSE: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("SSE connection failed: %s", resp.Status)
	}

	t.sseReader = resp.Body
	t.sseScanner = bufio.NewScanner(resp.Body)
	t.sseScanner.Split(scanSSEEvent)

	return nil
}

func (t *HTTPTransport) ReadRaw() (json.RawMessage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.sseScanner == nil {
		return nil, fmt.Errorf("SSE not connected")
	}

	for t.sseScanner.Scan() {
		data := t.sseScanner.Text()
		if data == "" {
			continue
		}

		if strings.HasPrefix(data, "data: ") {
			jsonData := strings.TrimPrefix(data, "data: ")
			return json.RawMessage(jsonData + "\n"), nil
		}
	}

	if err := t.sseScanner.Err(); err != nil {
		return nil, fmt.Errorf("SSE scan: %w", err)
	}

	return nil, io.EOF
}

func (t *HTTPTransport) EncodeRaw(raw json.RawMessage) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.reqID++

	req, err := http.NewRequest(http.MethodPost, t.url+"/message", strings.NewReader(string(raw)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %s: %s", resp.Status, string(body))
	}

	return nil
}

func (t *HTTPTransport) Close() error {
	if t.sseReader != nil {
		return t.sseReader.Close()
	}
	return nil
}

func (t *HTTPTransport) BaseURL() string {
	return t.url
}

func scanSSEEvent(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			return i + 2, data[:i], nil
		}
	}

	if atEOF {
		return len(data), data, nil
	}

	return 0, nil, nil
}

type MockTransport struct {
	input   chan json.RawMessage
	output  chan json.RawMessage
	waiting chan struct{}
}

func NewMockTransport() *MockTransport {
	return &MockTransport{
		input:   make(chan json.RawMessage, 32),
		output:  make(chan json.RawMessage, 32),
		waiting: make(chan struct{}, 1),
	}
}

func (m *MockTransport) ReadRaw() (json.RawMessage, error) {
	select {
	case msg := <-m.output:
		return msg, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("read timeout")
	}
}

func (m *MockTransport) EncodeRaw(raw json.RawMessage) error {
	select {
	case m.input <- raw:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("write timeout")
	}
}

func (m *MockTransport) Receive() <-chan json.RawMessage {
	return m.input
}

func (m *MockTransport) Send(raw json.RawMessage) {
	m.output <- raw
}

func (m *MockTransport) Close() error {
	close(m.input)
	close(m.output)
	return nil
}

func (m *MockTransport) ServeMCP() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		select {
		case m.input <- json.RawMessage(body):
		default:
		}

		var resp json.RawMessage
		select {
		case resp = <-m.output:
		case <-time.After(30 * time.Second):
			http.Error(w, "timeout", http.StatusGatewayTimeout)
			return
		}

		_, _ = w.Write(resp)
	}
}

func ParseTransportURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}
