#!/usr/bin/env bash
# MCP Visor harness — run from repository root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="${PATH:-}"
if command -v go >/dev/null 2>&1; then
  :
elif [[ -x /usr/local/go/bin/go ]]; then
  export PATH="/usr/local/go/bin:$PATH"
fi

if ! command -v go >/dev/null 2>&1; then
  echo "error: go not found on PATH" >&2
  exit 1
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
EVID_DIR="$ROOT/evidence/harness/$TS"
mkdir -p "$EVID_DIR"

LOG="$EVID_DIR/check.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== MCP Visor harness ==="
echo "root: $ROOT"
echo "time: $TS"
echo "go:   $(go version)"
echo

echo "--- make fmt ---"
make fmt

echo "--- make vet ---"
make vet

echo "--- make test ---"
make test

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git branch --show-current 2>/dev/null || echo unknown)"

cat >"$EVID_DIR/manifest.md" <<EOF
# Harness run $TS

- **Repository:** mcp-visor
- **Git:** \`$GIT_BRANCH\` @ \`$GIT_SHA\`
- **Commands:** \`make fmt\`, \`make vet\`, \`make test\`
- **Log:** \`check.log\` (same directory)

## Invariants (see \`harness/invariants.md\`)

Covered by tests in this run:

- H1 default deny — \`TestUnknownToolDenied\`
- H2 sensitive paths — \`TestSensitiveFileAccessDenied\`
- H3 read→send chain — chain_detection tests
- H5 audit redaction — \`TestAuditLogRedaction\`
- H6 proxy path — proxy_integration tests
- H9–H10 authorized source taint / pre-relay egress deny — \`internal/proxy/session_taint_test.go\`
- H11 audit hash chain — \`TestAuditLogHashChain\`
- H12 notification-form \`tools/call\` blocked (stdio + remote); non-tools notifications forward — \`TestInterceptDeniesNotificationToolsCallStdio\`, \`TestInterceptDeniesNotificationToolsCallRemoteParity\`, \`TestInterceptForwardsInitializedNotificationStdio\`, \`TestInterceptForwardsInitializedNotificationRemote\`, \`TestProxyIntegrationNotificationToolsCallNotRelayed\`

## Result

Harness completed successfully at $TS (UTC).
EOF

echo
echo "=== harness OK ==="
echo "manifest: $EVID_DIR/manifest.md"