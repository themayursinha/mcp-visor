#!/usr/bin/env bash
# H52 — canonical identity-aware harness.
#
# One command that proves the identity-aware path at the backend:
#
#   server_received(action) IMPLIES verified_actor(action) AND policy_allowed(action) AND durable_allow(action)
#
# It starts a real `visor serve` process against an independent observer backend
# (a separate process that records every tools/call it receives on the wire and
# imports nothing from this repository), drives the positive, negative and
# discriminating-control scenarios, and asserts the criterion from the observer's
# own artifact. A denial returned to the client for a call that had already been
# relayed fails this harness.
#
# Run from the repository root.
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
# Run-unique artifact directory. Scenario file names are fixed, so two runs in the
# same second sharing a directory would append to the same .jsonl files and each
# run's records would decide the other run's assertions.
RUN_ID="$$-$(date -u +%s%N)"
ART="$ROOT/evidence/harness/$TS/identity-aware-$RUN_ID"
mkdir -p "$ART"

echo "=== H52 identity-aware harness ==="
echo "root:    $ROOT"
echo "time:    $TS"
echo "go:      $(go version)"
echo "artifacts: $ART"
echo

# The observer artifact is written into the digest-excluded evidence tree, so this
# command cannot change the workspace snapshot digest the workflow binds.
set +e
H52_ARTIFACT_DIR="$ART" go test ./tests/integration/ \
  -count=1 -v -timeout 300s -run '^TestVerifiedActorBackendObserver$' 2>&1 \
  | tee "$ART/test.log"
STATUS="${PIPESTATUS[0]}"
set -e

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

{
  echo "# H52 identity-aware harness run $TS"
  echo
  echo "- **Git:** \`$GIT_SHA\`"
  echo "- **Command:** \`H52_ARTIFACT_DIR=$ART go test ./tests/integration/ -count=1 -v -timeout 300s -run ^TestVerifiedActorBackendObserver$\`"
  echo "- **Exit status:** $STATUS"
  echo
  echo "## Observer artifacts (one JSON line per tools/call the backend received)"
  echo
  if compgen -G "$ART/*.jsonl" >/dev/null; then
    for f in "$ART"/*.jsonl; do
      echo "- \`$(basename "$f")\`: $(wc -l <"$f" | tr -d ' ') received call(s)"
    done
  else
    echo "- none: the backend received no tools/call in any scenario"
  fi
  echo
  echo "An absent or empty artifact for a denied scenario is the expected evidence:"
  echo "the gate denied before relay. The positive and discriminating-control scenarios"
  echo "must show a received call, which is what proves the artifact path is live."
} >"$ART/manifest.md"

if [ "$STATUS" -ne 0 ]; then
  echo
  echo "=== identity-aware harness FAILED (exit $STATUS) ==="
  echo "manifest: $ART/manifest.md"
  exit "$STATUS"
fi

echo
echo "=== identity-aware harness OK ==="
echo "manifest: $ART/manifest.md"
