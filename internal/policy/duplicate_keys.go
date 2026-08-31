package policy

import (
	"bytes"
	"fmt"
)

// rejectDuplicateJSONKeys fails closed when any object in data repeats a key.
// encoding/json keeps the last duplicate; a downstream MCP decoder may keep
// the first. Authorization must not see a different destination set than the
// bytes that would be relayed.
func rejectDuplicateJSONKeys(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	var stack []map[string]bool
	i, n := 0, len(data)
	for i < n {
		c := data[i]
		switch c {
		case '{':
			stack = append(stack, map[string]bool{})
			i++
		case '}':
			if len(stack) == 0 {
				return fmt.Errorf("unbalanced object")
			}
			stack = stack[:len(stack)-1]
			i++
		case '"':
			start := i
			i++
			for i < n && data[i] != '"' {
				if data[i] == '\\' {
					i++
				}
				i++
			}
			if i >= n {
				return fmt.Errorf("unterminated string")
			}
			i++
			j := i
			for j < n && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < n && data[j] == ':' {
				if len(stack) == 0 {
					return fmt.Errorf("key outside object")
				}
				key := string(data[start:i])
				if stack[len(stack)-1][key] {
					return fmt.Errorf("duplicate key %s", key)
				}
				stack[len(stack)-1][key] = true
			}
		case '[', ']', ',', ':':
			i++
		case ' ', '\t', '\n', '\r':
			i++
		default:
			for i < n && data[i] != ',' && data[i] != '}' && data[i] != ']' &&
				data[i] != '{' && data[i] != '[' && data[i] != ':' && data[i] != '"' &&
				data[i] != ' ' && data[i] != '\t' && data[i] != '\n' && data[i] != '\r' {
				i++
			}
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("unclosed object")
	}
	return nil
}
