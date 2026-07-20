package approval

import (
	"sync"
	"testing"
	"time"
)

func TestGetPendingRequestExpiresSafelyUnderConcurrentAccess(t *testing.T) {
	de, err := NewDurableEngine(nil, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	de.pending["expired"] = &durableRequest{
		ID:        "expired",
		Tool:      "shell_exec",
		Server:    "shell",
		SessionID: "sess",
		AgentID:   "agent",
		ExpiresAt: time.Now().Add(-time.Second),
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := de.GetPendingRequest("expired"); err == nil {
				t.Error("expired pending request must not be returned")
			}
		}()
	}
	close(start)
	wg.Wait()
}
