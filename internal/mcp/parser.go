package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

type Parser struct {
	reader *bufio.Reader
	writer io.Writer
	last   []byte
}

func NewParser(r io.Reader, w io.Writer) *Parser {
	return &Parser{
		reader: bufio.NewReader(r),
		writer: w,
	}
}

func (p *Parser) ReadRaw() (json.RawMessage, error) {
	line, err := p.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	p.last = line
	if len(line) == 0 {
		return nil, fmt.Errorf("read: empty line")
	}
	return line, nil
}

func (p *Parser) LastRaw() json.RawMessage {
	return p.last
}

func (p *Parser) ReadMessage() (json.RawMessage, error) {
	return p.ReadRaw()
}

func (p *Parser) DecodeRequest(data json.RawMessage) (Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	if req.JSONRPC != JSONRPCVersion {
		return Request{}, fmt.Errorf("invalid jsonrpc version: %s", req.JSONRPC)
	}
	return req, nil
}

func (p *Parser) DecodeNotification(data json.RawMessage) (Notification, error) {
	var notif Notification
	if err := json.Unmarshal(data, &notif); err != nil {
		return Notification{}, fmt.Errorf("decode notification: %w", err)
	}
	return notif, nil
}

func (p *Parser) DecodeResponse(data json.RawMessage) (Response, error) {
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}

func (p *Parser) Write(raw json.RawMessage) error {
	n, err := p.writer.Write(raw)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if n != len(raw) {
		return fmt.Errorf("write: short (%d/%d)", n, len(raw))
	}
	return nil
}

func (p *Parser) EncodeResponse(resp Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	return p.Write(append(data, '\n'))
}

func (p *Parser) EncodeRequest(req Request) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	return p.Write(append(data, '\n'))
}

func (p *Parser) EncodeNotification(notif Notification) error {
	data, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("encode notification: %w", err)
	}
	return p.Write(append(data, '\n'))
}

func (p *Parser) EncodeRaw(data json.RawMessage) error {
	return p.Write(data)
}

func (p *Parser) ForwardRaw(data json.RawMessage) error {
	return p.Write(data)
}
