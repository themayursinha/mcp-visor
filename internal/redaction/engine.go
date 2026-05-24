package redaction

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/themayursinha/mcp-visor/internal/policy"
)

type Engine struct {
	patterns       []compiledPattern
	outputPatterns []compiledPattern
	sensitiveFiles []string
	filePatterns   []*regexp.Regexp
}

type compiledPattern struct {
	name    string
	regex   *regexp.Regexp
	replace string
}

type Result struct {
	Redacted        bool
	RedactedFields  []string
}

func NewEngine(redactCfg policy.RedactionConfig) *Engine {
	e := &Engine{
		sensitiveFiles: redactCfg.SensitiveFiles,
	}

	for _, p := range redactCfg.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		repl := p.Replacement
		if repl == "" {
			repl = "[REDACTED]"
		}
		e.patterns = append(e.patterns, compiledPattern{
			name:    p.Name,
			regex:   re,
			replace: repl,
		})
	}

	for _, p := range redactCfg.OutputPatterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		repl := p.Replacement
		if repl == "" {
			repl = "[REDACTED]"
		}
		e.outputPatterns = append(e.outputPatterns, compiledPattern{
			name:    p.Name,
			regex:   re,
			replace: repl,
		})
	}

	for _, pattern := range redactCfg.SensitiveFiles {
		re := compileGlobPattern(pattern)
		e.filePatterns = append(e.filePatterns, re)
	}

	return e
}

func NewEngineFromPolicy(p *policy.Policy) *Engine {
	return NewEngine(p.Redaction)
}

func (e *Engine) RedactArgs(args map[string]any) (map[string]any, Result) {
	result := Result{}
	out := make(map[string]any, len(args))
	for k, v := range args {
		redacted, fields := e.redactValue(k, v)
		out[k] = redacted
		if len(fields) > 0 {
			result.Redacted = true
			result.RedactedFields = append(result.RedactedFields, fields...)
		}
	}
	return out, result
}

func (e *Engine) RedactArgsJSON(raw json.RawMessage) (json.RawMessage, Result) {
	if len(raw) == 0 {
		return raw, Result{}
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return raw, Result{}
	}
	redacted, result := e.RedactArgs(args)
	if !result.Redacted {
		return raw, result
	}
	data, err := json.Marshal(redacted)
	if err != nil {
		return raw, result
	}
	return json.RawMessage(data), result
}

func (e *Engine) RedactOutput(text string) string {
	for _, p := range e.patterns {
		text = p.regex.ReplaceAllString(text, p.replace)
	}
	for _, p := range e.outputPatterns {
		text = p.regex.ReplaceAllString(text, p.replace)
	}
	return text
}

func (e *Engine) IsSensitiveFile(path string) bool {
	for _, re := range e.filePatterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (e *Engine) HasPatterns() bool {
	return len(e.patterns) > 0 || len(e.outputPatterns) > 0
}

func (e *Engine) redactValue(path string, v any) (any, []string) {
	switch val := v.(type) {
	case string:
		redacted, found := e.redactString(val)
		if found {
			return redacted, []string{path}
		}
		return val, nil
	case map[string]any:
		out := make(map[string]any, len(val))
		var fields []string
		for k, inner := range val {
			newPath := path + "." + k
			redacted, f := e.redactValue(newPath, inner)
			out[k] = redacted
			fields = append(fields, f...)
		}
		return out, fields
	case []any:
		out := make([]any, len(val))
		var fields []string
		for i, item := range val {
			newPath := path + "[0]"
			redacted, f := e.redactValue(newPath, item)
			out[i] = redacted
			fields = append(fields, f...)
			_ = i
			_ = newPath
		}
		return out, fields
	default:
		return v, nil
	}
}

func (e *Engine) redactString(s string) (string, bool) {
	original := s
	redacted := false
	for _, p := range e.patterns {
		if p.regex.MatchString(s) {
			s = p.regex.ReplaceAllString(s, p.replace)
			redacted = true
		}
	}
	if s != original {
		return s, true
	}
	return s, redacted
}

func compileGlobPattern(pattern string) *regexp.Regexp {
	s := regexp.QuoteMeta(pattern)
	s = strings.ReplaceAll(s, `\*\*`, `.*`)
	s = strings.ReplaceAll(s, `\*`, `[^/]*`)
	s = "(?i)^" + s + "$"
	re, err := regexp.Compile(s)
	if err != nil {
		re = regexp.MustCompile(regexp.QuoteMeta(pattern))
	}
	return re
}
