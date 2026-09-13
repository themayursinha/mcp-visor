# Agent identity lineage

H44 is the opt-in agent-identity lineage gate. A tool is lineage-gated only when its policy rules contain `type: lineage_require`. A gated `tools/call` denies before downstream relay unless R1 registered principal, R2 exact delegation ceiling, and R3 mandatory trajectory binding all pass.

The actor is the proxy/session client ID, never a claim inside `_lineage`. Capability and resource comparisons are byte-for-byte exact membership. `github.repo.read` cannot authorize the trusted `write_file`/`write` trajectory.

Lineage does not replace H32. When both are enabled, both must pass. An H32 failure remains terminal before lineage. Identity-less policies omit `Identity` and `Trajectories` from JSON and never lineage-gate.
