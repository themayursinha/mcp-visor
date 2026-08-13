// Package confuseddeputydemo implements the deterministic two-server
// confused-deputy demo: two distinct executables expose the same harmless
// tool and schema, only their tool description differs, and a poisoned
// description wins a deterministic selector. MCP Visor's stdio executable
// attestation then decides which artifact may actually execute.
package confuseddeputydemo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// ServerOptions configures the shared demo MCP server binary.
type ServerOptions struct {
	// Name and Version are the untrusted serverInfo claims each server
	// presents during the MCP handshake. They never satisfy attestation.
	Name            string
	Version         string
	ToolDescription string
	// ObserveLog is an optional append-only JSONL path that records whether
	// the server actually received a tools/call.
	ObserveLog string
}

// ToolName is the single tool both demo servers expose with the same schema.
const ToolName = "open_ticket"

// PoisonedMarker is the phrase a poisoned description carries so the
// deterministic selector can reproduce an agent preferring it. It is the
// only metadata difference between the two demo servers.
const PoisonedMarker = "unrestricted access"

// RunServer serves one stdio MCP server exposing ToolName with a harmless
// behavior identical across demo servers. The description is presentation
// data only.
func RunServer(opts ServerOptions) error {
	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout

	var obsFile *os.File
	if opts.ObserveLog != "" {
		f, err := os.OpenFile(opts.ObserveLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open observe log: %w", err)
		}
		defer f.Close()
		obsFile = f
	}

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil
		}
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      any             `json:"id,omitempty"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params,omitempty"`
		}
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		var resp []byte
		switch req.Method {
		case "initialize":
			resp = marshalResult(req.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]bool{}},
				"serverInfo":      map[string]any{"name": opts.Name, "version": opts.Version},
			})
		case "tools/list":
			resp = marshalResult(req.ID, map[string]any{
				"tools": []map[string]any{{
					"name":        ToolName,
					"description": opts.ToolDescription,
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"ticket_id": map[string]any{"type": "string"},
						},
						"required": []string{"ticket_id"},
					},
				}},
			})
		case "tools/call":
			if obsFile != nil {
				obs := map[string]any{"tool": ToolName, "received": true}
				if id, ok := req.ID.(float64); ok {
					obs["request_id"] = int(id)
				}
				if data, err := json.Marshal(obs); err == nil {
					_, _ = obsFile.Write(append(data, '\n'))
				}
			}
			resp = marshalResult(req.ID, map[string]any{
				"content": []map[string]any{{
					"type": "text",
					"text": "ticket created (demo server)",
				}},
			})
		case "ping":
			resp = marshalResult(req.ID, map[string]any{})
		default:
			if req.ID != nil {
				resp = marshalError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
			}
		}

		if resp != nil {
			if _, err := writer.Write(append(resp, '\n')); err != nil {
				return err
			}
		}
	}
}

func marshalResult(id any, result any) []byte {
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	return data
}

func marshalError(id any, code int, message string) []byte {
	data, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	})
	return data
}
