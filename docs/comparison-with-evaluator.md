# Comparison with mcp-llm-security-evaluator

This document explains the relationship between [mcp-visor](https://github.com/themayursinha/mcp-visor) and [mcp-llm-security-evaluator](https://github.com/themayursinha/mcp-llm-security-evaluator) — two complementary tools for MCP agent security.

## At a Glance

| | mcp-llm-security-evaluator | mcp-visor |
|---|---|---|
| **Purpose** | "Tells you what can go wrong" | "Stops dangerous MCP tool execution at runtime" |
| **Mode** | Offline analysis and simulation | Online/runtime enforcement |
| **LLM interaction** | Tests LLM responses to prompts | Does not interact with LLMs |
| **MCP integration** | Simulates mock tool calls | Proxies real MCP protocol traffic |
| **Policy role** | Assesses policy compliance of configs | Enforces policy before tool execution |
| **Output** | Reports, scores, findings | Allow/deny/approval decisions, audit logs |
| **When it runs** | CI/CD, on-demand scans | Every tool call in production |
| **Language** | Python | Go |
| **Deployment** | CLI tool, CI pipeline | Long-running daemon, Docker container |

## The Relationship

The evaluator is the **assessment** tool. It answers: "Is my MCP configuration safe? Is my agent susceptible to prompt injection? What tools should I restrict?"

The visor is the **enforcement** tool. It answers: "This specific tool call at this specific moment — should it proceed?"

They are designed to work together:

```
┌─────────────────────────┐
│  SECURITY ASSESSMENT     │
│  (evaluator)              │
│                           │
│  CI/CD pipeline           │
│  • Scans MCP configs     │
│  • Tests LLM responses   │   Informs ──▶  Policy Design
│  • Identifies risky tools│
│  • Generates findings    │                       │
└─────────────────────────┘                       ▼
                                        ┌─────────────────────────┐
                                        │  RUNTIME ENFORCEMENT     │
                                        │  (visor)                  │
                                        │                           │
                                        │  Every tool call          │
                                        │  • Enforces policy rules │
                                        │  • Blocks dangerous calls│
                                        │  • Detects tool chains   │
                                        │  • Redacts secrets       │
                                        │  • Generates audit logs  │
                                        └─────────────────────────┘
```

## When to Use Which

### Use the evaluator when:

- You are **designing** an MCP security policy for the first time
- You want to know **which tools are risky** in your configuration
- You need to **compare LLM providers** for prompt injection resistance
- You are **auditing** an existing MCP deployment
- You want to **generate findings** for a security review
- You are running **CI/CD checks** on MCP configuration changes

### Use the visor when:

- You are **running** an AI agent with MCP tools in production
- You want to **enforce** tool access policies at runtime
- You need a **deterministic** enforcement point that prompt injection cannot bypass
- You want to **detect** dangerous tool chains in real time
- You need structured audit events for denials, approvals, argument redactions, chain detections, session taints, and session lifecycle
- You want **human approval** for high-risk operations

## Using Both Together

The recommended workflow:

1. **Start with the evaluator**: Run it against your MCP configuration. It identifies risky tools, dangerous combinations, and prompt injection vulnerabilities.

2. **Design a visor policy**: Based on evaluator findings, decide which tools to allow, which to require approval for, and which to block. Configure chain detection rules based on the tool combinations the evaluator flagged.

3. **Deploy the visor**: Run it as the enforcement proxy in front of your MCP servers.

4. **Run the evaluator periodically**: Re-scan after configuration changes, agent updates, or new MCP server deployments. The evaluator identifies new risks; you update the visor policy accordingly.

```
                    ┌──────────────────────────┐
                    │  mcp-llm-security-        │
                    │  evaluator                │
                    │                           │
                    │  Runs:                    │
                    │  • On push to main        │
                    │  • Weekly scheduled scan  │
                    │  • On policy PR           │
                    └──────────┬───────────────┘
                               │
                      Findings report
                               │
                               ▼
                    ┌──────────────────────────┐
                    │  Policy update PR         │
                    │  (security team reviews)  │
                    └──────────┬───────────────┘
                               │
                               ▼
                    ┌──────────────────────────┐
                    │  mcp-visor                │
                    │                           │
                    │  Runs:                    │
                    │  • Continuously (daemon)  │
                    │  • Every tools/call       │
                    │  • Partially reloads      │
                    │    engine policy          │
                    └──────────────────────────┘
```

## Feature Comparison

| Feature | mcp-llm-security-evaluator | mcp-visor |
|---------|---------------------------|-----------|
| MCP proxy | No | Yes |
| Policy enforcement | No (assesses) | Yes (enforces) |
| Tool allowlist/denylist | Simulates | Enforces in real time |
| Chain detection | Flags possible chains in config | Detects chains in real tool call sequences |
| Secret redaction | Evaluates redaction accuracy | Strips secrets from live traffic |
| Human approval | No | Yes |
| Audit logging | Generates test reports | Emits selected structured security/session events; not yet a complete per-call ledger |
| LLM prompt injection testing | Yes | No (deterministic, no LLM) |
| LLM provider comparison | Yes | No |
| MCP config scanning | Yes | No |
| Configuration drift detection | Builds baseline from scans | Enforces current policy |
| Risk scoring of tools | Yes | Risk classification via policy |
| Compliance reporting | Yes | No (produces audit logs, not reports) |

## Security Model Differences

The evaluator actively tests LLMs against adversarial prompts. It **calls LLM APIs** and measures their resistance to manipulation. This means the evaluator:
- Requires API keys for LLM providers
- Sends potentially malicious prompts to LLMs
- Runs in a controlled CI/CD environment, not production

The visor never calls an LLM. Its policy engine is deterministic — exact match, regex, and rule-chain logic. This means the visor:
- Requires no LLM API key for the core enforcement path; optional integrations have their own credentials/endpoints
- Cannot be manipulated by prompt injection
- Runs continuously in the production tool execution path

## Why Separate Repositories

These are separate projects by design:

1. **Different audiences**: Evaluator is for security testers and compliance teams. Visor is for platform engineers and SREs.

2. **Different lifecycles**: Evaluator is a Python project with LLM SDK dependencies. Visor is a Go binary with a deterministic core and optional integration dependencies.

3. **Different threat models**: Evaluator requires LLM API keys. The visor core requires none; credentials for optional integrations must stay isolated from the policy decision path.

4. **Different deployment models**: Evaluator runs occasionally. Visor runs continuously. Different ops requirements.

5. **Clean conceptual separation**: Assessment vs. enforcement. Mixing them dilutes both messages.

## Summary

| Question | Answer |
|----------|--------|
| "Which tool should I use?" | Both. Evaluator for assessment, visor for enforcement. |
| "Can the visor replace the evaluator?" | No. The visor enforces policy; it doesn't assess configuration risk or test LLM responses. |
| "Can the evaluator replace the visor?" | No. The evaluator finds issues; it doesn't block tool execution at runtime. |
| "Do I need both?" | For a complete MCP security posture: yes. The evaluator tells you what policies to write. The visor enforces those policies. |

---

**Evaluator**: [github.com/themayursinha/mcp-llm-security-evaluator](https://github.com/themayursinha/mcp-llm-security-evaluator)

**Visor**: [github.com/themayursinha/mcp-visor](https://github.com/themayursinha/mcp-visor)
