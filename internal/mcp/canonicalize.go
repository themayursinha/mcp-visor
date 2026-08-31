package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// CanonicalizeJSONLine decodes JSON into a unique-key object and re-encodes it.
// encoding/json last-wins duplicate members and unescapes equivalent keys
// (\u0072ecipient vs recipient) into one map entry per decoded name.
// Trailing data after the first value fails closed.
// A trailing newline on the input is preserved so stdio line framing is kept.
func CanonicalizeJSONLine(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON")
		}
		return nil, fmt.Errorf("trailing JSON: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		out = append(out, '\n')
	}
	return out, nil
}
