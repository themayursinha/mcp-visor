package approval_test

import (
	"encoding/json"
	"testing"

	"github.com/themayursinha/mcp-visor/internal/approval"
	"github.com/themayursinha/mcp-visor/internal/receipt"
)

func FuzzDurableEngineRejectsUntrustedReceipts(f *testing.F) {
	f.Add([]byte(`{`))
	f.Add([]byte(`{"decision":"approve"}`))
	f.Add([]byte(`{"execution_id":"attacker-controlled","decision":"approve"}`))
	f.Add([]byte(`{"execution_id":"attacker-controlled","decision":"deny"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		de, err := approval.NewDurableEngine(nil, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := de.RequestApproval(approval.Request{
			ID: "fuzz", Tool: "shell_exec", Server: "shell", SessionID: "sess", AgentID: "agent",
			Reason: "high risk", RiskLevel: "high",
		})
		if err != nil {
			t.Fatal(err)
		}

		var candidate receipt.DecisionReceipt
		if err := json.Unmarshal(data, &candidate); err != nil {
			if decision, err := de.SubmitReceipt(data); err == nil || decision != nil {
				t.Fatal("malformed receipt must fail closed")
			}
			return
		}
		candidate.ExecutionID = pending.ExecutionID
		raw, err := candidate.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		decision, err := de.SubmitReceipt(raw)
		if err == nil || (decision != nil && decision.Approved) {
			t.Fatal("untrusted receipt must not approve a pending request")
		}
	})
}
