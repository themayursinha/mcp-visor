package transport

import (
	"encoding/json"
	"io"
)

type Message interface {
	json.Marshaler
}

type Transport interface {
	ReadRaw() (json.RawMessage, error)
	EncodeRaw(raw json.RawMessage) error
	Close() error
}

type PipeTransport struct {
	Reader io.ReadCloser
	Writer io.WriteCloser
	parser *lineParser
}

type lineParser struct {
	r io.Reader
	w io.Writer
}

func NewPipeTransport(r io.ReadCloser, w io.WriteCloser) *PipeTransport {
	return &PipeTransport{
		Reader: r,
		Writer: w,
		parser: &lineParser{r: r, w: w},
	}
}

func (t *PipeTransport) ReadRaw() (json.RawMessage, error) {
	return t.parser.ReadLine()
}

func (t *PipeTransport) EncodeRaw(raw json.RawMessage) error {
	return t.parser.WriteLine(raw)
}

func (t *PipeTransport) Close() error {
	var errs []error
	if err := t.Reader.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := t.Writer.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (p *lineParser) ReadLine() (json.RawMessage, error) {
	buf := make([]byte, 0, 4096)
	b := make([]byte, 1)
	for {
		n, err := p.r.Read(b)
		if err != nil {
			if len(buf) > 0 {
				return json.RawMessage(buf), nil
			}
			return nil, err
		}
		if n == 0 {
			if len(buf) > 0 {
				return json.RawMessage(buf), nil
			}
			continue
		}
		if b[0] == '\n' {
			if len(buf) > 0 {
				return json.RawMessage(buf), nil
			}
			continue
		}
		buf = append(buf, b[0])
	}
}

func (p *lineParser) WriteLine(data json.RawMessage) error {
	data = append(data, '\n')
	_, err := p.w.Write(data)
	return err
}
