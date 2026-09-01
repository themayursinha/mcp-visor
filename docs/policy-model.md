# MCP Visor Policy Model

Reference for the MCP Visor policy schema v1. Policy files are YAML documents that define exactly which MCP tools are allowed, under what conditions, with what restrictions.

## Schema Overview

```
version: "1.0"
description: "..."
default_action: deny | allow

settings:          # Global settings
servers:           # Server and tool definitions
  - name: "..."
    tools:
      - name: "..."
        risk: ...
        rules: ...
tool_chains:       # Chain detection rules
  - sources: ...
    sinks: ...
taints:            # Session state markers set by source tool calls
egress_controls:   # Stateful sink controls after taint
identities:        # Per-agent identity policies (optional)
redaction:         # Sensitive data detection patterns
time_restrictions: # Time-of-day access controls (optional)
```

## Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | No | Defaults to `"1.0"`. Other non-empty values are accepted; supported-version compatibility is not enforced. |
| `description` | string | No | Human-readable description of the policy. |
| `default_action` | string | No | Defaults to `"deny"`; may be `"deny"` or `"allow"`. |
| `settings` | object | No | Global settings (defaults applied if omitted). |
| `servers` | array | No | Defaults to an empty list; no configured server/tool rules then exist. |
| `tool_chains` | array | No | Chain detection rules for dangerous tool sequences. |
| `taints` | array | No | Session state markers set when source tools access sensitive data. |
| `egress_controls` | array | No | Stateful sink controls triggered by existing session taints. |
| `identities` | array | No | Per-agent identity-based access control. |
| `time_restrictions` | array | No | Time-of-day or day-of-week access restrictions. |
| `redaction` | object | No | Sensitive data detection and redaction configuration. |

## Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_argument_size_bytes` | int | 1048576 | Max tool call argument size (1 MB). Measured on the original `params` object bytes before unique-key collapse (duplicate `arguments` members and padding count). Larger calls rejected. |
| `max_output_size_bytes` | int | 10485760 | Truncation threshold for each textual `Content[].Text`; a marker is appended after truncation, so final text can exceed the threshold. Not an aggregate/structured/error limit. |
| `session_max_tools` | int | 100 | Max tool calls per session. New calls denied after limit. |
| `session_timeout_seconds` | int | 3600 | Session timeout (1 hour). |
| `approval_timeout_seconds` | int | 300 | Approval timeout (5 minutes). Deny after timeout. |
| `chain_window_size` | int | 10 | Number of previous calls to inspect for chain detection. |
| `log_level` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error`. |

## Servers

Each server entry defines an MCP server and its tools:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Server identifier matching the MCP command. |
| `transport` | string | No | `"stdio"` (local child process) or `"http"` (remote HTTP+SSE). |
| `allowed` | bool | Yes | Whether this server is allowed (`true`/`false`). |
| `allowed_destinations` | array | No | Declared in the schema but not evaluated by the current engine. Do not rely on it for network control. |
| `denied_destinations` | array | No | Declared in the schema but not evaluated by the current engine. Do not rely on it for network control. |
| `tools` | array | Yes | Tool-specific rules for this server. |

### Tool Rules

Each tool in a server's `tools` list:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Tool name as registered in the MCP server. |
| `allowed` | bool | Yes | Whether this tool is allowed (`true`/`false`). |
| `risk` | string | No | Risk classification: `"critical"`, `"high"`, `"medium"`, `"low"`. If omitted, inferred from tool name. |
| `approval_required` | bool | No | Require human approval before every execution. |
| `rules` | array | No | Argument validation rules. |

## Argument Rule Types

The engine enforces 19 rule types. The linter currently recognizes one additional name, `deny_command_pattern_composite`, that has no enforcement case; do not use it until that mismatch is fixed.

### `deny_path` / `allow_path`

Control filesystem access by path patterns. Supports `*` (single-level) and `**` (recursive) globs, case-insensitive.

```yaml
rules:
  - type: deny_path
    patterns:
      - "/etc/passwd"
      - "/etc/shadow"
      - "**/.env"
      - "**/.ssh/**"
      - "**/*.pem"
      - "**/*.key"
  - type: allow_path
    patterns:
      - "/home/user/projects/**"
      - "/tmp/mcp-safe/**"
```

Policy path rules match argument keys `path`, `file`, and `file_path`. The separate built-in sensitive-file check also inspects `uri`. They treat the value as a glob match only: a schema-valid string containing shell grammar can still match `/workspace/**`. That is not PATH→SHELL amplification detection. Use `require_path_literal` when the tool implementation interpolates a path into a command.

### `require_path_literal`

Fail-closed PATH-class slot: the argument must remain a path literal. Attaching this rule is the implementation attestation that the tool's path inputs must not be interpreted as shell. Visor does not inspect the MCP server binary.

This is the bounded CVE-2026-18482 slice. Semantic classes PATH, URL, IDENTIFIER, QUERY, TEMPLATE, COMMAND, CREDENTIAL, and POLICY are vocabulary for argument-to-effect reasoning. Only PATH→SHELL is enforced here. URL→network, STRING→SQL, STRING→template, IDENTIFIER→IAM, and MODEL_DATA→HOST_CODE (including CVE-2026-61539 eval injection) are out of scope.

Fail-closed:

- missing, non-string, or blank value in any PATH-class alias → deny
- **every present alias is checked**; a literal `path` does not cover shell grammar in `absolutePath` or `AbsolutePath`
- any value containing ASCII shell grammar (separators, substitution, redirection, quotes, `#`, NUL, CR/LF) → deny with evidence `argument class PATH`, `effect class SHELL`, `authority transition PATH->SHELL`

This is not a shell parser. Unicode homoglyphs, percent-encoding, and glob-only characters (`*`, `?`) are out of scope. Parentheses in otherwise-literal filenames deny.

```yaml
rules:
  - type: require_path_literal
```

Matched against argument keys: `path`, `file`, `file_path`, `filepath`, `absolute_path`, `absolutepath`, matched case-insensitively (so `absolutePath` and `AbsolutePath` are the same slot as `absolutepath`). The `uri` key is not consulted (URL class). `allow_path` / `deny_path` still use first-match `path` / `file` / `file_path` only.

Example fixture: [`examples/policies/path-shell-amplification.yaml`](../examples/policies/path-shell-amplification.yaml).

### `allow_path_slot`

Fail-closed PATH/TARGET-class glob allowlist for a mandated effect path. A tool that is allowed to clean `/tmp/agent-123` must not delete `$HOME`. Declared path fields are the effect target; Visor does not expand shell variables inside the MCP server, look up inodes, or distinguish ephemeral vs persistent storage. Attaching this rule is the effect bound. Matching uses the same globs as `allow_path` and is fail-closed:

- missing, non-string, or blank value in any PATH/TARGET-class alias → deny
- empty allowlist → deny
- **every present alias is checked**; a mandated path in `path` does not cover `$HOME` in `target`
- any value that does not match a mandate glob → deny with evidence `argument class PATH`, `effect class DESTRUCTIVE`, `authority transition MANDATE->COLLATERAL`

```yaml
rules:
  - type: allow_path_slot
    patterns:
      - "/tmp/agent-123"
      - "/tmp/agent-123/**"
```

Matched against argument keys: `path`, `file`, `file_path`, `filepath`, `absolute_path`, `absolutepath`, `target`, `dir`, `directory`, matched case-insensitively (so `Target` is the same slot as `target`). `allow_path` / `deny_path` still use first-match `path` / `file` / `file_path` only and skip the rule when those keys are absent. Command strings (`command` / `cmd` / `exec`) are not parsed. Path canonicalization, `..` traversal, and symlink identity are out of scope.

Example fixture: [`examples/policies/destructive-path-slot.yaml`](../examples/policies/destructive-path-slot.yaml).

### `allow_destination`

Fail-closed URL/HOST-class exact-host allowlist for a mandated egress host. A tool that is allowed to reach `docs.internal` must not post to `evil.example`. Declared destination fields are the effect host; Visor does not follow redirects, resolve DNS, or parse destinations out of `command` / `cmd` / `exec`. Attaching this rule is the effect bound. Matching is exact host (trim + case-insensitive), not substring:

- missing, non-string, blank, or unparseable host in any URL/HOST-class alias → deny
- empty allowlist → deny
- **every present alias is checked**; a mandated host in `url` does not cover `evil.example` in `host`
- any host that is not an exact allowlisted name (including suffix spoofs) → deny with evidence `argument class URL`, `effect class NETWORK`, `authority transition MANDATE->EGRESS`

```yaml
rules:
  - type: allow_destination
    patterns:
      - "docs.internal"
```

Matched against argument keys: `url`, `uri`, `host`, `hostname`, `endpoint`, `dest`, `dest_host`, `destination`, `domain`, matched case-insensitively (so `URL` is the same slot as `url`). `to` is not a destination alias (mailbox). The value is a boring host, or a leading `scheme://` followed by boring `host` or `host:port` (letters, digits, dots, hyphens). `://` in the middle of the string is unparseable. Userinfo (`@`), backslash, percent-encoding, brackets, and whitespace make the host unparseable and deny. Visor does not adopt WHATWG or `net/url` semantics for a downstream tool. Server-level `allowed_destinations` / `denied_destinations` remain inert. Nested maps are out of model.

Example fixture: [`examples/policies/reward-seeker-destination.yaml`](../examples/policies/reward-seeker-destination.yaml).

### `deny_command_pattern` / `allow_command_pattern`

Regex-based shell command filtering. Case-insensitive. Patterns are regex, not globs.

```yaml
rules:
  - type: deny_command_pattern
    patterns:
      - "bash\\s+-i\\s+>&"
      - "rm\\s+-rf\\s+/"
      - "curl.*\\|.*(bash|sh)"
      - "nc\\s+-[nl]"
  - type: allow_command_pattern
    patterns:
      - "^ls\\s"
      - "^cat\\s"
      - "^echo\\s"
      - "^git\\s(status|log|diff|branch)"
```

Matched against argument keys: `command`, `cmd`, `exec`.

### `deny_command_keyword`

Keyword-based shell command filtering. Simpler than regex; checks if command string contains any keyword (case-insensitive).

```yaml
rules:
  - type: deny_command_keyword
    keywords:
      - "reverse shell"
      - "backdoor"
      - "bind shell"
```

### `deny_query_pattern` / `allow_query_pattern`

Regex-based SQL/database query filtering. Case-insensitive.

```yaml
rules:
  - type: deny_query_pattern
    patterns:
      - "DROP\\s+(TABLE|DATABASE)"
      - "DELETE\\s+FROM"
      - "TRUNCATE\\s+TABLE"
  - type: allow_query_pattern
    patterns:
      - "^SELECT\\s"
      - "^EXPLAIN\\s"
      - "^SHOW\\s"
```

Matched against argument keys: `query`, `sql`, `statement`.

### `allowed_repos`

Restrict GitHub operations to specific repositories.

```yaml
rules:
  - type: allowed_repos
    repos:
      - "acme-corp/service-a"
      - "acme-corp/service-b"
      - "acme-corp/docs"
```

Matched against argument keys: `repo`, `repository`, `owner/repo`.

### `deny_recipient_domain` / `allow_recipient_domain`

Control email/Slack message destinations by domain.

```yaml
rules:
  - type: deny_recipient_domain
    domains:
      - "competitor.com"
      - "personal-email.com"
  - type: allow_recipient_domain
    domains:
      - "acme-corp.com"
```

Matched against argument keys: `recipient`, `to`, `email`, `domain`. Domain matching is substring-based (`strings.Contains`); it is not an exact mailbox allowlist.

### `allow_recipient`

Exact mailbox allowlist for a mandated recipient slot. Untrusted observations may fill this value; they must not enlarge it. Unlike `allow_recipient_domain`, matching is exact (trim + case-insensitive) and fail-closed:

- missing, non-string, or blank value in any of `recipient`/`to`/`email`/`cc`/`bcc` (matched case-insensitively, so `To` is the same slot as `to`) → deny
- empty allowlist → deny
- **every present alias is checked**; a mandated mailbox in `recipient` does not cover an attacker mailbox in `to`, `To`, `email`, `cc`, or `bcc`
- before Evaluate and relay, a `tools/call` request is canonicalized to a unique-key decoded object (duplicate members, escaped-equivalent keys such as `\u0072ecipient`, and duplicate `params.arguments` collapse the same way). Authorization and the forwarded bytes are that object, so a first-wins decoder cannot observe a destination Evaluate discarded
- any value that is not an exact allowlisted mailbox → deny (including `attacker@example.com` when only `finance@example.com` is listed)

```yaml
rules:
  - type: allow_recipient
    patterns:
      - "finance@example.com"
```

Matched against argument keys: `recipient`, `to`, `email`, `cc`, `bcc`, matched case-insensitively. The `domain` key is not consulted. Display-name forms (`Name <addr>`), comma-separated lists, arrays, and RFC 5322 parsing are out of scope: those inputs deny.

Example mandate fixture: [`examples/policies/authority-non-escalation.yaml`](../examples/policies/authority-non-escalation.yaml).

### `allow_resource_owner`

Exact principal allowlist for a mandated owner slot. A tool that is allowed to act for alice must not cancel bob. Declared owner fields are the ownership signal; Visor does not look up a world model or call a live booking API. Attaching this rule is the effect bound. Matching is exact (trim + case-insensitive) and fail-closed:

- missing, non-string, or blank value in any PRINCIPAL-class alias → deny
- empty allowlist → deny
- **every present alias is checked**; a mandated principal in `owner` does not cover another principal in `user_id` or `userId`
- any value that is not an exact allowlisted principal → deny with evidence `argument class PRINCIPAL`, `effect class THIRD_PARTY`, `authority transition USER->OTHER`

```yaml
rules:
  - type: allow_resource_owner
    patterns:
      - "alice"
```

Matched against argument keys: `owner`, `user_id`, `userid`, `resource_owner`, `account_id`, `principal`, matched case-insensitively (so `userId` is the same slot as `userid`; `user_id` is a distinct alias). This is not `allowed_repos` `owner/repo`. Reservation IDs, class IDs, and other identifiers are not consulted. Arrays, objects, and non-string owners deny.

Example fixture: [`examples/policies/third-party-effect.yaml`](../examples/policies/third-party-effect.yaml).

### `max_file_size`

Reject file reads/writes exceeding a byte limit.

```yaml
rules:
  - type: max_file_size
    bytes: 5242880   # 5 MB
```

Matched against argument keys: `size`, `content_length`, `file_size`.

### `max_result_rows` / `max_export_rows`

Reject database queries whose result row count exceeds the limit.

```yaml
rules:
  - type: max_result_rows
    rows: 1000
  - type: max_export_rows
    rows: 100
```

Matched against argument keys: `limit`, `rows`, `count`, `max_results`.

### `require_approval_always`

Force human approval for every call to this tool. No additional configuration needed.

```yaml
rules:
  - type: require_approval_always
```

This rule does not skip later deny rules. `Evaluate` folds every stage the same way: deny stops; require_approval is remembered; allow continues; an empty or unsupported action (including omitted `outside_action` on a matching time restriction, or `redact_then_allow`) is a fail-closed deny. YAML order and later stages cannot turn a would-be deny into an approvable relay, or turn pending approval into a proxy default-allow. The tool-level `approval_required: true` flag is folded the same way.

## Risk Classification

Tools are classified into risk tiers. If not explicitly set, risk is inferred from the tool name.

| Risk Level | Description | Examples |
|------------|-------------|----------|
| `critical` | Shell execution, cloud IAM, destructive operations | `shell_exec`, `aws_iam_create_user`, `file_delete` |
| `high` | File writes, network sends, database writes | `file_write`, `http_post`, `slack_send_message`, `gmail_send` |
| `medium` | Reads, searches, navigation | `file_read`, `database_query`, `browser_navigate` |
| `low` | Read-only discovery operations | `tools_list`, `github_read_code`, `aws_s3_list_buckets` |
| `unknown` | Unregistered tool (default-deny unless overridden) | Any tool not in the policy |

### Inference Rules

If no risk is set explicitly, the engine scans the tool name for keywords:

- Contains `delete`, `drop`, `iam`, `shell`, `exec`, `sudo`, `root` → `critical`
- Contains `write`, `send`, `post`, `create`, `modify`, `query`, `secret`, `credential`, `token` → `high`
- Contains `read`, `fetch`, `get`, `search`, `download`, `ssh`, `connect` → `medium`
- Otherwise → `low`

## Chain Detection

Chain rules detect dangerous sequences of tool calls within a session.

```yaml
tool_chains:
  - name: "prevent_exfiltration_via_http"
    description: "Block file_read followed by http_post"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "http_post"
    action: deny
    within_calls: 3
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique rule identifier. |
| `description` | string | No | Human-readable description. |
| `sources` | array | Yes | Tool calls that trigger the chain (must precede sink). |
| `sinks` | array | Yes | Tool calls that complete the chain (trigger action). |
| `action` | string | Yes | `"deny"` or `"require_approval"`. |
| `within_calls` | int | Yes | Lookback window size for source matches. |

### Source/Sink Matching

Each source/sink match rule has:

| Field | Type | Description |
|-------|------|-------------|
| `server` | string | Server name or `"*"` for any server. |
| `tool_pattern` | string | Regex pattern matching tool names. Case-insensitive. |

### Default Chain Rules

Chain detection is configurable. No chain rules fire unless defined in policy. Common patterns:

| Source | Sink | Rationale |
|--------|------|-----------|
| `file_read` | `http_post` | Data exfiltration via HTTP |
| `file_read` | `slack_send_message` | Data leak to messaging |
| `database_query` | `http_post` | Database dump to external endpoint |
| `env_read` | `browser_navigate` | Secrets leaked via browser |
| `*_read` | `*_delete` | Read-then-destroy pattern |

## Session Taints and Egress Controls

Taints let policy remember what the agent has already touched in this session. Egress controls then change later authorization decisions based on that state.

```yaml
taints:
  - name: "sensitive_file_accessed"
    description: "Session has accessed sensitive workspace data"
    source_tools: ["file_read"]
    source_patterns:
      - "**/customer-secrets/**"
      - "**/secrets/**"

egress_controls:
  - name: "block_sensitive_egress"
    description: "Block outbound sends after sensitive access"
    when_tainted: "sensitive_file_accessed"
    sink_tools: ["http_post", "slack_send_message"]
    action: deny
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `taints[].name` | string | Yes | Taint identifier stored on the session. |
| `taints[].source_servers` | array | No | Source server names or `"*"`. Omit to match any server. |
| `taints[].source_tools` | array | Yes | Source tool names/patterns that can mark the session. |
| `taints[].source_patterns` | array | No | Glob patterns matched against string argument values. |
| `egress_controls[].name` | string | Yes | Control identifier, included in audit events. |
| `egress_controls[].when_tainted` | string | Yes | Taint that must already exist on the session. |
| `egress_controls[].sink_servers` | array | No | Sink server names/patterns. Omit to match any server. |
| `egress_controls[].sink_tools` | array | Yes | Sink tool names/patterns to gate. |
| `egress_controls[].action` | string | Yes | `"deny"` or `"require_approval"`. |

Audit events for taint-triggered denials include `session_taints`, `taint_source`, `taint_reason`, and `policy_rule`.

## Identity-Based Access

Restrict tool access per agent identity. Only tools/servers listed in the identity's allowlists are permitted.

```yaml
identities:
  - name: "github-copilot-dev"
    description: "Standard developer agent"
    allowed_servers:
      - "filesystem"
      - "github"
    allowed_tools:
      - "filesystem/file_read"
      - "filesystem/file_write"
      - "github/github_read_code"
      - "github/github_create_pr"
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Identity name (matched against `--client-id`). |
| `description` | string | No | Human-readable description. |
| `allowed_servers` | array | Yes | Server names this identity can use. |
| `allowed_tools` | array | Yes | Fully qualified tool names (`server/tool`). |

## Time Restrictions

Restrict tool access by time of day or day of week.

```yaml
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
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Rule identifier. |
| `description` | string | No | Human-readable description. |
| `servers` | array | Yes | Server names affected. |
| `tools` | array | Yes | Tool names affected. |
| `allowed_hours` | array | No | Time windows when access is permitted. |
| `denied_days` | array | No | Days when access is denied (e.g., `["saturday", "sunday"]`). |
| `outside_action` | string | Yes | `"deny"` or `"require_approval"` when the restriction matches. Loader still accepts an omitted value; if a matching restriction then fires, `Evaluate` fail-closes with deny rather than returning an empty action the proxy would default-allow. `redact_then_allow` is not an Evaluate action and also denies. |

Time window fields:

| Field | Type | Description |
|-------|------|-------------|
| `start` | string | Start time in 24-hour format (`HH:MM`). |
| `end` | string | End time in 24-hour format (`HH:MM`). |
| `timezone` | string | IANA timezone (e.g., `"America/New_York"`). |
| `days` | array | Days of week (lowercase English). |

## Redaction

Configure sensitive data detection and redaction.

```yaml
redaction:
  patterns:
    - name: "openai_api_key"
      regex: "sk-[a-zA-Z0-9_-]{20,}"
      replacement: "[REDACTED: OpenAI API Key]"
    - name: "github_token"
      regex: "ghp_[a-zA-Z0-9]{36}"
      replacement: "[REDACTED: GitHub Token]"
    - name: "jwt_token"
      regex: "eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+"
      replacement: "[REDACTED: JWT Token]"

  output_redaction: true
  output_patterns:
    - name: "secrets_in_output"
      regex: "(password|secret|token|key|credential)\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?"
      replacement: "$1=[REDACTED]"

  sensitive_files:
    - "**/.env"
    - "**/.env.*"
    - "**/credentials"
    - "**/.aws/credentials"
    - "**/.ssh/**"
    - "**/*.pem"
    - "**/*.key"
    - "**/.docker/config.json"
    - "**/kubeconfig"
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `patterns` | array | No | Regex patterns for redacting tool call arguments. |
| `output_redaction` | bool | No | Declared in policy but not consulted by the current redaction engine. Configured input and output patterns are applied to outputs regardless of this value. |
| `output_patterns` | array | No | Regex patterns for redacting tool outputs. |
| `sensitive_files` | array | No | Glob patterns for files that should be completely blocked. |

### Redaction Pattern Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique pattern name for audit logs. |
| `regex` | string | Go regex pattern. |
| `replacement` | string | Text to substitute for matched content. |

### Built-in Redaction Patterns

These patterns are built into the redaction engine and active by default:

| Pattern | Detects |
|---------|---------|
| OpenAI API key | `sk-[a-zA-Z0-9_-]{20,}` |
| GitHub token | `ghp_[a-zA-Z0-9]{36}` |
| Slack token | `xox[baprs]-[a-zA-Z0-9-]+` |
| AWS access key | `AKIA[0-9A-Z]{16}` |
| JWT token | `eyJ...eyJ...` structure |
| Private key | `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----` |
| DB connection string | `mongodb://`, `postgresql://`, `mysql://`, `redis://`, `jdbc://` with credentials |
| Internal IP | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` |


## Decision Model

Every valid JSON-RPC `tools/call` request with an `id` reaches a terminal `allow`, `deny`, or `require_approval` decision. Notification-form `tools/call` is blocked at the envelope gate (no relay). Recognizable malformed `tools/call` attempts with an `id` fail closed with an error response. Input redaction is applied before policy evaluation; when redaction occurs the terminal audit event includes the redacted fields in its reason.

| Decision | Meaning |
|----------|---------|
| `allow` | Tool call is permitted. Durably committed to the audit sink, then forwarded to the server. |
| `deny` | Tool call is blocked. Error returned to client. |
| `require_approval` | Tool call is held. Proceeds only on human approval. |

Decisions include a `reason` field explaining _why_ the decision was made for auditability.

## Evaluation Order

The proxy applies checks in this order:

1. Optional stdio identity attestation — mismatch or unresolved identity denies before argument policy
2. Runtime limits — argument size, session call count, and session timeout
3. Argument redaction — secrets are removed from the payload prepared for relay
4. Built-in sensitive-path block
5. Policy evaluation — server/tool allow rules and argument validation. This currently evaluates the originally parsed arguments, not the rewritten relay payload. `Evaluate` folds argument rules, identity, time restrictions, and `approval_required` the same way: deny stops; require_approval is remembered; allow continues; any other action is a fail-closed deny. Approval is returned only if no stage denied.
6. Existing session taints checked against egress controls
7. Chain detection against recent calls authorized for relay
8. Approval check
9. Durable allow-commit — terminal `tool_call_allowed` is fully appended and `Sync()`'d; failure denies with zero relay and does not mark taints
10. Post-allow taint marking for matching source tools
11. Relay to the MCP server

Session history is appended after authorization but before the transport write. It therefore represents calls authorized for relay, including a call whose transport write later fails.

The first terminal deny stops relay. Input redaction does not emit a premature allow event; only the terminal decision is written, with redaction noted on that event when applicable (H15). Output-only redaction still has no dedicated JSONL event.

## Complete Example

```yaml
version: "1.0"
description: "Production policy for development agents"
default_action: deny

settings:
  chain_window_size: 5
  approval_timeout_seconds: 120

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
              - "**/.env"
              - "**/.ssh/**"
              - "**/*.pem"
          - type: allow_path
            patterns:
              - "/home/user/**"
              - "/tmp/**"

      - name: "file_write"
        allowed: true
        risk: high
        approval_required: true
        rules:
          - type: deny_path
            patterns:
              - "/etc/**"
              - "/usr/**"
          - type: allow_path
            patterns:
              - "/home/user/**"
              - "/tmp/**"

  - name: "slack"
    transport: http
    allowed: true
    tools:
      - name: "slack_send_message"
        allowed: true
        risk: high
        approval_required: true

      - name: "slack_read_messages"
        allowed: true
        risk: medium

tool_chains:
  - name: "prevent_exfiltration_via_http"
    sources:
      - server: "*"
        tool_pattern: "file_read"
    sinks:
      - server: "*"
        tool_pattern: "http_post"
    action: deny
    within_calls: 3

  - name: "prevent_exfiltration_via_slack"
    sources:
      - server: "*"
        tool_pattern: "(file_read|database_query)"
    sinks:
      - server: "slack"
        tool_pattern: "slack_send_message"
    action: deny
    within_calls: 3

redaction:
  output_redaction: true
  sensitive_files:
    - "**/.env"
    - "**/credentials"
    - "**/*.pem"
    - "**/*.key"
    - "**/.ssh/**"
```

## Example Policies

The repository includes example policies demonstrating different postures:

| Policy | Path | Default | Behavior |
|--------|------|---------|----------|
| Strict Deny | `examples/policies/strict-deny.yaml` | deny | Deny everything by default. |
| Developer Medium | `examples/policies/developer-medium.yaml` | deny | Allow reads, deny writes, approve network. |
| Demo Policy | `examples/policies/demo-policy.yaml` | deny | Permissive demo configuration. |
| Session Taint Egress | `examples/policies/session-taint-egress.yaml` | deny | Sensitive read marks session; later egress is blocked. |
| Third-Party Effect | `examples/policies/third-party-effect.yaml` | deny | Book/cancel only for the mandate principal. |
| Destructive Path Slot | `examples/policies/destructive-path-slot.yaml` | deny | Clean only under the mandate path glob. |
| Reward-Seeker Destination | `examples/policies/reward-seeker-destination.yaml` | deny | Local file_read allowed; egress only to the mandate host. |

## Error Handling

- **Invalid YAML**: Policy file fails to parse → rejected with line/column error
- **Schema validation failure**: Missing required fields, wrong types → rejected with field-level error
- **Invalid regex**: the loader does not compile all rule, chain, or redaction regexes. `mcp-visor lint --strict` catches several cases, but `serve` does not run lint automatically. Invalid deny/chain regexes can behave as no match, and invalid redaction regexes are skipped.
- **Unknown rule type**: loader succeeds and the engine ignores the rule.

Invalid YAML and schema-validation errors prevent startup. Lint remains supplemental: plain lint can succeed with warnings; `--strict --no-warnings` can suppress warning failures; and `deny_command_pattern_composite` is recognized without enforcement, so even strict lint is not a complete fail-closed gate.
