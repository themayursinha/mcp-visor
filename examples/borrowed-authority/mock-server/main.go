// Command mock-server is the borrowed-authority demo fixture: tenant-B's
// MCP server exposing calculator (decoy), read_secret, and internal_fetch.
// Every tools/call is recorded to the observe log before responding, so the
// demo can prove denied calls never arrived.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	observeLog := flag.String("observe-log", "", "path to append-only server observation JSONL log")
	flag.Parse()

	var obsFile *os.File
	if *observeLog != "" {
		f, err := os.OpenFile(*observeLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mock-server: cannot open observe-log: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		obsFile = f
	}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024*1024), 1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	seq := 0
	for in.Scan() {
		line := append([]byte{}, in.Bytes()...)
		if len(bytesTrim(line)) == 0 {
			continue
		}
		var req struct {
			ID     any             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		var response []byte
		switch req.Method {
		case "initialize":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"protocolVersion": "2024-11-05", "serverInfo": map[string]any{"name": "tenant-b-server", "version": "1.0.0"}},
			})
		case "tools/list":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"tools": []map[string]any{
					{"name": "calculator", "description": "Tenant A decoy calculator", "inputSchema": map[string]any{"type": "object"}},
					{"name": "read_secret", "description": "Tenant B secret reader", "inputSchema": map[string]any{"type": "object"}},
					{"name": "internal_fetch", "description": "Tenant B scoped fetcher", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}}}},
				}},
			})
		case "tools/call":
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments,omitempty"`
			}
			if err := json.Unmarshal(req.Params, &params); err != nil {
				continue
			}
			seq++
			if obsFile != nil {
				obs := map[string]any{"request_seq": seq, "tool": params.Name, "received": true}
				if id, ok := req.ID.(float64); ok {
					obs["request_id"] = int(id)
				}
				if data, err := json.Marshal(obs); err == nil {
					obsFile.Write(append(data, '\n'))
				}
			}
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"content": []map[string]any{
					{"type": "text", "text": fmt.Sprintf("tenant-B result for '%s'", params.Name)},
				}},
			})
		case "notifications/initialized":
			continue
		default:
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": -32601, "message": "method not found"},
			})
		}
		out.Write(append(response, '\n'))
		out.Flush()
	}
}

func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mock-server: marshal: %v\n", err)
		os.Exit(1)
	}
	return data
}

func bytesTrim(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	j := len(b)
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r' || b[j-1] == '\n') {
		j--
	}
	return b[i:j]
}
