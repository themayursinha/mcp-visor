package trace

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MessageDirection string

const (
	DirClientToServer MessageDirection = "C->S"
	DirServerToClient MessageDirection = "S->C"
	DirInternal       MessageDirection = "INT"
)

type Event struct {
	Direction MessageDirection `json:"direction"`
	Method    string           `json:"method,omitempty"`
	JSONRPC   string           `json:"jsonrpc,omitempty"`
	ID        any              `json:"id,omitempty"`
	Raw       string           `json:"raw,omitempty"`
	Error     string           `json:"error,omitempty"`
}

func (e *Event) Summarize() string {
	switch e.Direction {
	case DirClientToServer, DirServerToClient:
		if e.Error != "" {
			return fmt.Sprintf("%s error(id=%v): %s", e.Direction, e.ID, e.Error)
		}
		if e.ID == nil {
			return fmt.Sprintf("%s notification", e.Direction)
		}
		return fmt.Sprintf("%s %s(id=%v)", e.Direction, e.Method, e.ID)
	default:
		return fmt.Sprintf("%s %s", e.Direction, e.Method)
	}
}

type TraceLogger interface {
	Log(*Event)
}

type TextLogger struct{}

func (TextLogger) Log(e *Event) {
	fmt.Printf("[TRACE] %s | %s\n", e.Direction, e.Summarize())
	if e.Raw != "" {
		for _, line := range strings.Split(e.Raw, "\n") {
			if line != "" {
				fmt.Printf("         %s\n", line)
			}
		}
	}
}

type JSONLLogger struct{}

func (JSONLLogger) Log(e *Event) {
	data, _ := json.Marshal(e)
	fmt.Printf("%s\n", string(data))
}

type SummaryLogger struct {
	messages int
	byMethod map[string]int
	byDir    map[MessageDirection]int
	errors   int
	bytesIn  int
}

func NewSummaryLogger() *SummaryLogger {
	return &SummaryLogger{
		byMethod: make(map[string]int),
		byDir:    make(map[MessageDirection]int),
	}
}

func (s *SummaryLogger) Log(e *Event) {
	s.messages++
	s.byDir[e.Direction]++
	s.bytesIn += len(e.Raw)

	if e.Method != "" {
		s.byMethod[e.Method]++
	}
	if e.Error != "" {
		s.errors++
	}
}

func (s *SummaryLogger) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "messages: %d\n", s.messages)
	fmt.Fprintf(&b, "bytes: %d\n", s.bytesIn)
	fmt.Fprintf(&b, "errors: %d\n", s.errors)
	b.WriteString("by direction:\n")
	for dir, count := range s.byDir {
		fmt.Fprintf(&b, "  %s: %d\n", dir, count)
	}
	b.WriteString("by method:\n")
	for method, count := range s.byMethod {
		fmt.Fprintf(&b, "  %s: %d\n", method, count)
	}
	return b.String()
}

type HexDumper struct{}

func (HexDumper) Dump(data []byte) string {
	var lines []string
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		hex := ""
		for _, b := range chunk {
			hex += fmt.Sprintf("%02x ", b)
		}
		if len(chunk) < 16 {
			hex += strings.Repeat("   ", 16-len(chunk))
		}

		ascii := ""
		for _, b := range chunk {
			if b >= 32 && b <= 126 {
				ascii += string(b)
			} else {
				ascii += "."
			}
		}

		lines = append(lines, fmt.Sprintf("%04x:  %s  |%s|", i, hex, ascii))
	}
	return strings.Join(lines, "\n")
}

func LogEvent(logger TraceLogger, direction MessageDirection, method, jsonrpc string, id any, raw []byte, err error) {
	e := &Event{
		Direction: direction,
		Method:    method,
		JSONRPC:   jsonrpc,
		ID:        id,
	}
	if raw != nil {
		e.Raw = strings.TrimSpace(string(raw))
	}
	if err != nil {
		e.Error = err.Error()
	}
	logger.Log(e)
}
