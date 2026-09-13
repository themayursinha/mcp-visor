package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/themayursinha/mcp-visor/internal/audit"
	"github.com/themayursinha/mcp-visor/internal/killswitch"
	"github.com/themayursinha/mcp-visor/internal/mcp"
	"github.com/themayursinha/mcp-visor/internal/policy"
)

var kineticBeforePersist func()

func (p *Proxy) initKineticStop(cfg Config) {
	if cfg.KillSwitchDir == "" {
		if len(cfg.KillSwitchControllers) > 0 || cfg.SessionEpoch != 0 {
			p.kineticInitErr = fmt.Errorf("kill-switch-controller and session-epoch require kill-switch-dir")
		}
		return
	}
	if !p.audit.Durable() {
		p.kineticInitErr = fmt.Errorf("kinetic stop requires a durable audit log")
		return
	}
	if cfg.ServerURL != "" {
		p.kineticInitErr = fmt.Errorf("kinetic stop is not supported with remote servers")
		return
	}
	if p.kineticSessionEmpty || cfg.SessionID == "" {
		p.kineticInitErr = fmt.Errorf("kinetic stop requires an explicit session-id")
		return
	}
	if cfg.SessionEpoch < 1 {
		p.kineticInitErr = fmt.Errorf("kinetic stop requires session-epoch >= 1")
		return
	}
	if len(cfg.KillSwitchControllers) == 0 {
		p.kineticInitErr = fmt.Errorf("kinetic stop requires at least one controller")
		return
	}
	ctrls := make(map[string][]byte, len(cfg.KillSwitchControllers))
	for _, c := range cfg.KillSwitchControllers {
		if c.ID == "" || len(c.Key) != 32 {
			p.kineticInitErr = fmt.Errorf("kinetic stop: invalid controller")
			return
		}
		if _, dup := ctrls[c.ID]; dup {
			p.kineticInitErr = fmt.Errorf("kinetic stop: duplicate controller id")
			return
		}
		ctrls[c.ID] = c.Key
	}
	mon, err := killswitch.NewMonitor(killswitch.Config{
		Dir:          cfg.KillSwitchDir,
		SessionID:    cfg.SessionID,
		SessionEpoch: cfg.SessionEpoch,
		Controllers:  ctrls,
	})
	if err != nil {
		p.kineticInitErr = err
		return
	}
	p.kineticMon = mon
}

func (p *Proxy) kineticEnabled() bool {
	return p.cfg.KillSwitchDir != "" && p.kineticInitErr == nil && p.kineticMon != nil
}

func (p *Proxy) kineticGate() (bool, string) {
	if p.cfg.KillSwitchDir == "" || !p.kineticRevoked.Load() {
		return false, ""
	}
	return true, fmt.Sprintf("kinetic stop: session %s epoch %d is revoked", p.cfg.SessionID, p.cfg.SessionEpoch)
}

func (p *Proxy) beginKineticRun(ctx context.Context) (context.Context, error) {
	if p.kineticInitErr != nil {
		return ctx, fmt.Errorf("kinetic stop initialization: %w", p.kineticInitErr)
	}
	if !p.kineticEnabled() {
		return ctx, nil
	}
	ctx, p.sessionCancel = context.WithCancel(ctx)
	p.sessionCtx = ctx
	if err := p.kineticMon.StartupCheck(); err != nil {
		return ctx, fmt.Errorf("kinetic stop initialization: %w", err)
	}
	return ctx, nil
}

func (p *Proxy) runKineticMonitor(ctx context.Context) error {
	if p.kineticMon == nil {
		return nil
	}
	err := p.kineticMon.Run(ctx, p.enforceKineticStop)
	if ke := p.kineticEnforcedError(); ke != nil {
		return ke
	}
	return err
}

func (p *Proxy) enforceKineticStop(stop killswitch.Stop) {
	p.kineticStopOnce.Do(func() {
		p.kineticPersistWG.Add(1)
		observed := stop.ObservedAt.UTC()
		if observed.IsZero() {
			observed = time.Now().UTC()
		}
		func() {
			defer p.kineticPersistWG.Done()
			p.kineticRevoked.Store(true)
			p.kineticRunMu.Lock()
			p.kineticRunErr = fmt.Errorf("kinetic stop enforced: %s", stop.ResultingState)
			p.kineticRunMu.Unlock()
			if p.sessionCancel != nil {
				p.sessionCancel()
			}
			p.containSupervisedProcess()
			p.kineticRunMu.Lock()
			p.kineticRunErr = fmt.Errorf("kinetic stop enforced: %s", stop.ResultingState)
			p.kineticRunMu.Unlock()
			if kineticBeforePersist != nil {
				kineticBeforePersist()
			}

			ev := audit.Event{
				EventType:               audit.EventKineticStopEnforced,
				SessionID:               p.cfg.SessionID,
				AgentID:                 p.cfg.ClientID,
				Server:                  p.cfg.ServerName,
				Decision:                "revoked",
				Reason:                  stop.Command.Reason,
				ControllerID:            stop.Command.ControllerID,
				CommandID:               stop.Command.CommandID,
				SessionEpoch:            p.cfg.SessionEpoch,
				RevokedThroughEpoch:     stop.Command.RevokeThroughEpoch,
				ObservedEnforcementTime: observed.Format(time.RFC3339Nano),
				ResultingState:          stop.ResultingState,
				ControlRequestSHA256:    stop.RequestSHA256,
			}
			auditErr := p.audit.CommitKineticStop(ev)
			var persistErr error
			if auditErr == nil {
				if stop.ResultingState == "revoked_contained" && p.kineticMon != nil {
					persistErr = p.kineticMon.WriteState(stop)
				}
				p.forwardAudit(ev)
			}
			out := persistErr
			if auditErr != nil {
				out = auditErr
			}
			p.kineticRunMu.Lock()
			if out != nil {
				p.kineticRunErr = out
			} else {
				p.kineticRunErr = fmt.Errorf("kinetic stop enforced: %s", stop.ResultingState)
			}
			p.kineticRunMu.Unlock()
		}()
		p.runtimeMu.Lock()
		p.kineticRevokedThru = stop.Command.RevokeThroughEpoch
		p.kineticReason = stop.Command.Reason
		p.kineticResult = stop.ResultingState
		p.kineticObserved = observed
		p.runtimeMu.Unlock()
	})
}

func (p *Proxy) registerSupervisedProcess(cmd *exec.Cmd) {
	p.supervisedMu.Lock()
	p.supervisedCmd = cmd
	p.supervisedMu.Unlock()
}

func (p *Proxy) closeSupervisedPipes() {
	p.supervisedMu.Lock()
	stdin := p.supervisedStdin
	pipes := append([]io.Closer(nil), p.supervisedPipes...)
	p.supervisedMu.Unlock()
	if stdin != nil {
		_ = stdin.Close()
	}
	for _, c := range pipes {
		if c != nil {
			_ = c.Close()
		}
	}
}

func (p *Proxy) killSupervisedLocked() {
	p.supervisedMu.Lock()
	cmd := p.supervisedCmd
	p.supervisedMu.Unlock()
	killKineticProcess(cmd)
}

func (p *Proxy) containSupervisedProcess() {
	p.closeSupervisedPipes()
	p.kineticIOMu.Lock()
	defer p.kineticIOMu.Unlock()
	p.killSupervisedLocked()
}

func (p *Proxy) encodeIfNotRevoked(encode func(json.RawMessage) error, raw json.RawMessage) error {
	p.kineticIOMu.Lock()
	defer p.kineticIOMu.Unlock()
	if p.kineticEnabled() && p.kineticRevoked.Load() {
		return fmt.Errorf("kinetic stop: encode refused")
	}
	return encode(raw)
}

func (p *Proxy) startSupervised(cmd *exec.Cmd, stdin, stdout, stderr io.Closer) error {
	p.kineticIOMu.Lock()
	defer p.kineticIOMu.Unlock()
	if p.kineticEnabled() && p.kineticRevoked.Load() {
		return fmt.Errorf("kinetic stop: refused launch")
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	if !p.kineticEnabled() {
		return nil
	}
	p.registerSupervisedProcess(cmd)
	p.supervisedMu.Lock()
	p.supervisedStdin = stdin
	if stdout != nil {
		p.supervisedPipes = append(p.supervisedPipes, stdout)
	}
	if stderr != nil {
		p.supervisedPipes = append(p.supervisedPipes, stderr)
	}
	p.supervisedMu.Unlock()
	if p.kineticRevoked.Load() {
		p.closeSupervisedPipes()
		p.killSupervisedLocked()
		return fmt.Errorf("kinetic stop: refused launch")
	}
	return nil
}

func (p *Proxy) readRawUntilStop(read func() (json.RawMessage, error)) (json.RawMessage, error) {
	ctx := p.sessionCtx
	if ctx == nil {
		return read()
	}
	type result struct {
		raw json.RawMessage
		err error
	}
	ch := make(chan result, 1)
	go func() { raw, err := read(); ch <- result{raw, err} }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.raw, r.err
	}
}

func (p *Proxy) kineticEnforcedError() error {
	p.kineticRunMu.Lock()
	defer p.kineticRunMu.Unlock()
	return p.kineticRunErr
}

func (p *Proxy) kineticOr(err error) error {
	if p.kineticEnforcedError() != nil {
		p.kineticPersistWG.Wait()
	}
	if ke := p.kineticEnforcedError(); ke != nil {
		return ke
	}
	return err
}

func (p *Proxy) denyKineticRevoked(req mcp.Request, callReq mcp.ToolsCallRequest, raw json.RawMessage, respond toolsCallResponder, release func(), serverName, reason string, started time.Time) (json.RawMessage, string) {
	respond(req.ID, reason)
	p.metrics.IncrementDenied()
	ev := audit.Event{
		EventType: audit.EventToolDenied,
		SessionID: p.session.ID,
		AgentID:   p.cfg.ClientID,
		Server:    serverName,
		Tool:      callReq.Name,
		Decision:  string(policy.ActionDeny),
		Reason:    reason,
	}
	_ = p.audit.Log(ev)
	release()
	p.forwardAudit(ev)
	p.observeToolCall("denied", reason, serverName, callReq.Name, string(policy.RiskUnknown), false, started)
	return raw, "denied"
}
