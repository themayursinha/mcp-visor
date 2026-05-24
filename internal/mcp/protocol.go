package mcp

import "encoding/json"

const (
	JSONRPCVersion = "2.0"

	MethodInitialize          = "initialize"
	MethodInitialized         = "notifications/initialized"
	MethodToolsList           = "tools/list"
	MethodToolsCall           = "tools/call"
	MethodResourcesList       = "resources/list"
	MethodResourcesRead       = "resources/read"
	MethodResourcesTemplates  = "resources/templates/list"
	MethodPromptsList         = "prompts/list"
	MethodPromptsGet          = "prompts/get"
	MethodLoggingSetLevel     = "logging/setLevel"
	MethodPing               = "ping"
	MethodCancelled           = "notifications/cancelled"
	MethodRootsList           = "roots/list"

	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type InitializeRequest struct {
	ProtocolVersion string        `json:"protocolVersion"`
	Capabilities    Capabilities  `json:"capabilities"`
	ClientInfo      Implementation `json:"clientInfo"`
}

type InitializeResult struct {
	ProtocolVersion string        `json:"protocolVersion"`
	Capabilities    Capabilities  `json:"capabilities"`
	ServerInfo      Implementation `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
	Logging   *struct{}            `json:"logging,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ToolsListRequest struct{}

type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string  `json:"nextCursor,omitempty"`
}

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type ToolsCallRequest struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type ToolsCallResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Data     string `json:"data,omitempty"`
}

type PingRequest struct{}
type PingResult struct{}

func NewErrorResponse(id any, code int, message string) Response {
	return Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	}
}

func NewResultResponse(id any, result any) Response {
	data, _ := json.Marshal(result)
	return Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  data,
	}
}

func (r Request) IsNotification() bool {
	return r.ID == nil
}

func (r Request) RequestID() any {
	return r.ID
}

func NewPingRequest(id any) Request {
	return Request{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Method:  MethodPing,
	}
}
