# Agent identity lineage

H44 is the opt-in agent-identity lineage gate. A tool is lineage-gated only when its policy rules contain `type: lineage_require`. A gated `tools/call` denies before downstream relay unless R1 registered principal, R2 exact delegation ceiling, and R3 mandatory trajectory binding all pass.

H44 proves authorization against an operator-bound session identity (`--client-id`). It does not authenticate the underlying agent process.

The actor is the proxy/session client ID, never a claim inside `_lineage`. Capability and resource comparisons are byte-for-byte exact membership. `github.repo.read` cannot authorize the trusted `write_file`/`write` trajectory.

Root grants (`parent_grant_id` empty) must be issued by the human principal **and** name a root agent (`parent_agent_id` empty). A human root grant to a child agent that already declares a parent is rejected at registry load.

After a human approval returns, lineage is revalidated with a fresh clock against the same immutable policy snapshot, immediately before the durable allow commit. A stale pre-wait lineage allow never authorizes. Post-approval ownership and delegation denials keep that snapshot-redacted lineage evidence.

Lineage does not replace H32. When both are enabled, both must pass. An H32 failure remains terminal before lineage. Identity-less policies omit `Identity` and `Trajectories` from JSON and never lineage-gate.
