package siem

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
)

type Format string

const (
	FormatSyslog5424 Format = "syslog-rfc5424"
	FormatJSON       Format = "json"
	FormatCEF        Format = "cef"
)

type Exporter struct {
	mu       sync.Mutex
	format   Format
	writers  []writer
	hostname string
	appName  string
}

type writer interface {
	Write([]byte) (int, error)
	Close() error
}

type tcpWriter struct {
	conn net.Conn
}

func (w *tcpWriter) Write(data []byte) (int, error) {
	return w.conn.Write(data)
}

func (w *tcpWriter) Close() error {
	return w.conn.Close()
}

type udpWriter struct {
	conn net.Conn
}

func (w *udpWriter) Write(data []byte) (int, error) {
	return w.conn.Write(data)
}

func (w *udpWriter) Close() error {
	return w.conn.Close()
}

type fileWriter struct {
	f *os.File
}

func (w *fileWriter) Write(data []byte) (int, error) {
	return w.f.Write(data)
}

func (w *fileWriter) Close() error {
	return w.f.Close()
}

type Config struct {
	Format   Format
	Targets  []string
	Hostname string
	AppName  string
}

func DefaultConfig() Config {
	hostname, _ := os.Hostname()
	return Config{
		Format:   FormatJSON,
		Hostname: hostname,
		AppName:  "mcp-visor",
	}
}

func NewExporter(cfg Config) (*Exporter, error) {
	if cfg.Hostname == "" {
		hostname, _ := os.Hostname()
		cfg.Hostname = hostname
	}
	if cfg.AppName == "" {
		cfg.AppName = "mcp-visor"
	}
	if cfg.Format == "" {
		cfg.Format = FormatJSON
	}

	exp := &Exporter{
		format:   cfg.Format,
		hostname: cfg.Hostname,
		appName:  cfg.AppName,
	}

	for _, target := range cfg.Targets {
		w, err := createWriter(target)
		if err != nil {
			return nil, fmt.Errorf("create writer for %s: %w", target, err)
		}
		exp.writers = append(exp.writers, w)
	}

	return exp, nil
}

func MustExporter(cfg Config) *Exporter {
	exp, err := NewExporter(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "siem exporter: %v\n", err)
		return &Exporter{format: cfg.Format}
	}
	return exp
}

func createWriter(target string) (writer, error) {
	if len(target) > 4 && target[:4] == "tcp:" {
		conn, err := net.Dial("tcp", target[4:])
		if err != nil {
			return nil, fmt.Errorf("dial tcp %s: %w", target[4:], err)
		}
		return &tcpWriter{conn: conn}, nil
	}
	if len(target) > 4 && target[:4] == "udp:" {
		conn, err := net.Dial("udp", target[4:])
		if err != nil {
			return nil, fmt.Errorf("dial udp %s: %w", target[4:], err)
		}
		return &udpWriter{conn: conn}, nil
	}
	f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", target, err)
	}
	return &fileWriter{f: f}, nil
}

func (e *Exporter) Export(event audit.Event) error {
	if len(e.writers) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var line []byte
	switch e.format {
	case FormatSyslog5424:
		line = e.formatSyslog5424(event)
	case FormatJSON:
		line = e.formatJSON(event)
	case FormatCEF:
		line = e.formatCEF(event)
	default:
		line = e.formatJSON(event)
	}

	line = append(line, '\n')

	for _, w := range e.writers {
		if _, err := w.Write(line); err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}
	return nil
}

func (e *Exporter) formatSyslog5424(event audit.Event) []byte {
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	severity := syslogSeverity(event)
	facility := 1

	pri := facility*8 + severity
	header := fmt.Sprintf("<%d>1 %s %s %s %d mcp_visor [mcp-visor@1 session_id=\"%s\" agent_id=\"%s\"]",
		pri, ts, e.hostname, e.appName, os.Getpid(), event.SessionID, event.AgentID)

	msg := fmt.Sprintf(" %s: %s", event.Decision, event.Reason)
	if event.Tool != "" {
		msg = fmt.Sprintf(" tool=%s server=%s %s: %s", event.Tool, event.Server, event.Decision, event.Reason)
	}

	return []byte(header + msg)
}

func (e *Exporter) formatJSON(event audit.Event) []byte {
	envelope := map[string]any{
		"timestamp":  event.Timestamp,
		"event_type": string(event.EventType),
		"session_id": event.SessionID,
		"agent_id":   event.AgentID,
		"server":     event.Server,
		"tool":       event.Tool,
		"decision":   event.Decision,
		"reason":     event.Reason,
		"risk_level": event.RiskLevel,
		"hostname":   e.hostname,
		"app":        e.appName,
	}

	data, _ := json.Marshal(envelope)
	return data
}

func (e *Exporter) formatCEF(event audit.Event) []byte {
	name := string(event.EventType)
	severity := cefSeverity(event)

	extensions := fmt.Sprintf("suser=%s duser=%s request=%s act=%s reason=%s cs1=%s cs1Label=RiskLevel",
		event.SessionID, event.AgentID, event.Tool, event.Decision, event.Reason, event.RiskLevel)

	cef := fmt.Sprintf("CEF:0|MCP|mcp-visor|1.0|%s|%s|%d|%s",
		name, event.Decision, severity, extensions)

	return []byte(cef)
}

func (e *Exporter) Close() error {
	for _, w := range e.writers {
		w.Close()
	}
	return nil
}

func syslogSeverity(event audit.Event) int {
	switch event.EventType {
	case audit.EventToolDenied, audit.EventToolChainDetected:
		return 4
	case audit.EventToolApprovalRequired:
		return 5
	default:
		return 6
	}
}

func cefSeverity(event audit.Event) int {
	switch event.RiskLevel {
	case "critical":
		return 10
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 5
	}
}
