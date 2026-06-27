package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

type Emitter struct {
	urls       []string
	hmacKey    []byte
	httpClient *http.Client
	eventCh    chan EventPayload
	done       chan struct{}
}

type EventPayload struct {
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	SessionID string         `json:"session_id"`
	AgentID   string         `json:"agent_id"`
	Server    string         `json:"server"`
	Tool      string         `json:"tool,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Decision  string         `json:"policy_decision"`
	Reason    string         `json:"reason,omitempty"`
	RiskLevel string         `json:"risk_level,omitempty"`
	Message   string         `json:"message,omitempty"`
}

type Config struct {
	URLs           []string
	HMACSecret     string
	RequestTimeout time.Duration
	BufferSize     int
}

func DefaultConfig() Config {
	return Config{
		RequestTimeout: 10 * time.Second,
		BufferSize:     256,
	}
}

func NewEmitter(cfg Config) *Emitter {
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 256
	}

	e := &Emitter{
		urls: cfg.URLs,
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
		eventCh: make(chan EventPayload, cfg.BufferSize),
		done:    make(chan struct{}),
	}

	if cfg.HMACSecret != "" {
		e.hmacKey = []byte(cfg.HMACSecret)
	}

	go e.loop()
	return e
}

func (e *Emitter) Emit(event audit.Event) {
	payload := EventPayload{
		Timestamp: event.Timestamp,
		EventType: string(event.EventType),
		SessionID: event.SessionID,
		AgentID:   event.AgentID,
		Server:    event.Server,
		Tool:      event.Tool,
		Arguments: event.Arguments,
		Decision:  event.Decision,
		Reason:    event.Reason,
		RiskLevel: event.RiskLevel,
		Message:   event.Message,
	}

	select {
	case e.eventCh <- payload:
	default:
	}
}

func (e *Emitter) EmitDirect(event audit.Event) error {
	payload := EventPayload{
		Timestamp: event.Timestamp,
		EventType: string(event.EventType),
		SessionID: event.SessionID,
		AgentID:   event.AgentID,
		Server:    event.Server,
		Tool:      event.Tool,
		Arguments: event.Arguments,
		Decision:  event.Decision,
		Reason:    event.Reason,
		RiskLevel: event.RiskLevel,
		Message:   event.Message,
	}

	return e.deliver(payload)
}

func (e *Emitter) Close() {
	close(e.done)
}

func (e *Emitter) loop() {
	for {
		select {
		case <-e.done:
			return
		case payload := <-e.eventCh:
			if err := e.deliver(payload); err != nil {
				go func() {
					time.Sleep(1 * time.Second)
					select {
					case e.eventCh <- payload:
					default:
					}
				}()
			}
		}
	}
}

func (e *Emitter) deliver(payload EventPayload) error {
	if payload.Timestamp == "" {
		payload.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	for _, url := range e.urls {
		if err := e.postWithRetry(url, body, 3); err != nil {
			return fmt.Errorf("post to %s: %w", url, err)
		}
	}
	return nil
}

func (e *Emitter) postWithRetry(url string, body []byte, retries int) error {
	var lastErr error
	for i := 0; i < retries; i++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		if len(e.hmacKey) > 0 {
			mac := hmac.New(sha256.New, e.hmacKey)
			mac.Write(body)
			sig := hex.EncodeToString(mac.Sum(nil))
			req.Header.Set("X-MCP-Visor-Signature", sig)
		}

		resp, err := e.httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("non-2xx response: %d", resp.StatusCode)
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}
	return lastErr
}
