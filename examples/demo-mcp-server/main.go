package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout
	requestID := 0

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "mock-server: read error: %v\n", err)
			return
		}

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      any             `json:"id,omitempty"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params,omitempty"`
		}
		if err := json.Unmarshal(line, &req); err != nil {
			fmt.Fprintf(os.Stderr, "mock-server: decode error: %v\n", err)
			continue
		}
		requestID++
		_ = requestID

		var response []byte

		switch req.Method {
		case "initialize":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": "2024-11-05",
					"capabilities": map[string]any{
						"tools": map[string]bool{},
					},
					"serverInfo": map[string]any{
						"name":    "mock-mcp-server",
						"version": "1.0.0",
					},
				},
			})

		case "tools/list":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"tools": []map[string]any{
						{
							"name":        "file_read",
							"description": "Read a file from the filesystem",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"path": map[string]any{
										"type": "string",
									},
								},
							},
						},
						{
							"name":        "http_post",
							"description": "Send an HTTP POST request",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"url":  map[string]any{"type": "string"},
									"body": map[string]any{"type": "string"},
								},
							},
						},
						{
							"name":        "shell_exec",
							"description": "Execute a shell command",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"command": map[string]any{"type": "string"},
								},
							},
						},
						{
							"name":        "slack_send_message",
							"description": "Send a message to a Slack channel",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"channel": map[string]any{"type": "string"},
									"text":    map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			})

		case "tools/call":
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments,omitempty"`
			}
			_ = json.Unmarshal(req.Params, &params)

			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"content": []map[string]any{
						{
							"type": "text",
							"text": fmt.Sprintf("Mock result for tool '%s': executed successfully", params.Name),
						},
					},
				},
			})

		case "resources/list":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"resources": []any{}},
			})

		case "resources/read":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"contents": []map[string]any{
						{"uri": "mock://test", "text": "mock content"},
					},
				},
			})

		case "prompts/list":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"prompts": []any{}},
			})

		case "ping":
			response = mustMarshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{},
			})

		default:
			if req.ID != nil {
				response = mustMarshal(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error": map[string]any{
						"code":    -32601,
						"message": fmt.Sprintf("Method not found: %s", req.Method),
					},
				})
			}
		}

		if response != nil {
			if _, err := writer.Write(append(response, '\n')); err != nil {
				fmt.Fprintf(os.Stderr, "mock-server: write error: %v\n", err)
				return
			}
		}
	}
}

func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
