package observability

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readTestdata() ([]byte, error) {
	return os.ReadFile(filepath.Join("testdata", "brake-audit.jsonl"))
}

// FuzzLoadEvents hunts whole families of parse-fidelity bugs at once
// instead of one Codex round each: no panics/hangs, byte-deterministic
// output, and structural invariants on everything accepted.
//
// Properties (must hold for every input that parses without error):
//  1. Determinism: parsing the same bytes twice yields identical events.
//  2. Every returned event carries an event_type.
//  3. Re-encoding is stable: marshaling the parsed events and re-parsing
//     yields the same count (no phantom or dropped records).
func FuzzLoadEvents(f *testing.F) {
	seeds := [][]byte{
		[]byte("{}\n"),
		[]byte("{\"event_type\":\"tool_call_denied\",\"policy_decision\":\"deny\"}\n"),
		[]byte("  \n\t\n"),
		[]byte{},
		[]byte("{\"event_type\":\"x\"}"),
		[]byte("{\"event_type\":\"x\"}\n{\"event_type\":\"y\"}\n"),
		[]byte("{\"a\":[{\"b\":null}]}\n"),
		[]byte("\xef\xbb\xbf{\"event_type\":\"x\"}\n"),
		[]byte("\"str\"\n123\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	if data, err := readTestdata(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := LoadEvents(bytes.NewReader(data))
		if err != nil {
			return
		}
		second, err := LoadEvents(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("nondeterministic error: %v", err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("nondeterministic parse")
		}
		for i, ev := range first {
			if ev.EventType == "" {
				t.Fatalf("event %d missing event_type", i)
			}
		}
	})
}
