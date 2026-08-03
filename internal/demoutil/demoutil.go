// Package demoutil provides types and validation used by both the demo-runner
// and its integration tests.
package demoutil

import (
	"errors"
	"fmt"
)

// ObsLine represents one observation from the synthetic MCP server.
type ObsLine struct {
	Tool      string
	RequestID int
	Received  bool
}

// ValidateObservations checks that the expected calls reached the server
// and the denied call did not.
func ValidateObservations(obs []ObsLine) error {
	if len(obs) == 0 {
		return errors.New("observation log is empty")
	}
	find := func(tool string, id int) bool {
		for _, o := range obs {
			if o.Tool == tool && o.RequestID == id {
				return o.Received
			}
		}
		return false
	}
	if !find("file_read", 100) {
		return errors.New("file_read #100 was not received by server")
	}
	if !find("file_read", 200) {
		return errors.New("file_read #200 was not received by server")
	}
	if find("http_post", 300) {
		return errors.New("http_post #300 was received — egress control did not work")
	}
	return nil
}

// DemoEvidence holds parsed fields from audit events.
type DemoEvidence struct {
	Taint      string
	SourceTool string
	SinkTool   string
	Rule       string
	Decision   string
}

// ValidateEvidence checks all required evidence fields are present.
func ValidateEvidence(ev *DemoEvidence) error {
	if ev.Taint == "" {
		return errors.New("missing taint event in audit log")
	}
	if ev.SourceTool == "" {
		return errors.New("missing source_tool in taint event")
	}
	if ev.SinkTool == "" {
		return errors.New("missing sink_tool in denial event")
	}
	if ev.Rule == "" {
		return errors.New("missing rule in denial event")
	}
	if ev.Decision != "deny" {
		return fmt.Errorf("expected decision=deny, got %q", ev.Decision)
	}
	return nil
}
