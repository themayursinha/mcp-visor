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
# own artifact. A denial returned to the client is not enough: if the completed
# observer session shows the backend received the call, the harness fails. An
# incomplete session fails the harness as unmeasured; it never counts as a
# denial.
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

# Complete only when the artifact ends with an `end` record whose prefix byte
# count and digest match. Count only tools/call records. Anything else is
# incomplete (unmeasured); never treated as a denial.
h52_artifact_status() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "unmeasured (python3 unavailable)"
    return 0
  fi
  python3 - "$1" <<'PY'
import hashlib, json, sys

def unmeasured():
    print("incomplete (unmeasured)")
    raise SystemExit(0)

path = sys.argv[1]
try:
    raw = open(path, "rb").read()
except OSError:
    unmeasured()
if not raw.strip():
    unmeasured()
trimmed = raw[:-1] if raw.endswith(b"\n") else raw
idx = trimmed.rfind(b"\n")
if idx < 0:
    prefix, end_line = b"", trimmed
else:
    prefix, end_line = trimmed[: idx + 1], trimmed[idx + 1 :]
try:
    term = json.loads(end_line)
except Exception:
    unmeasured()
if not isinstance(term, dict) or term.get("event") != "end":
    unmeasured()
digest = hashlib.sha256(prefix).hexdigest()
if term.get("bytes") != len(prefix) or term.get("sha256") != digest:
    unmeasured()
n = 0
for line in prefix.split(b"\n"):
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        unmeasured()
    if obj.get("record") == "call":
        n += 1
print("complete, %d tools/call record(s)" % n)
PY
}

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

# go test exits 0 when -run selects nothing, so a green exit is not evidence
# that the named test ran. A narrowed -run (or a rename/removal) otherwise
# turns one subtest into a green suite: require the root PASS line, the PASS
# line of every published scenario, and a minimum subtest count of 20.
if [ "$STATUS" -eq 0 ]; then
  if ! grep -q -- '--- PASS: TestVerifiedActorBackendObserver (' "$ART/test.log" \
      || ! grep -q -- '--- PASS: TestVerifiedActorBackendObserver/' "$ART/test.log"; then
    echo "error: TestVerifiedActorBackendObserver: the harness measured nothing" >&2
    STATUS=1
  else
    H52_REQUIRED_SUBTESTS=(
      observer_tools_call_then_eof_writes_end
      observer_stdin_left_open_has_no_terminal_record
      observer_unparsable_line_writes_observer_error
      deny_against_complete_session_that_contains_the_id
      forwarded_against_complete_zero_call_session
      stdout_pipe_parent_is_unknown_not_a_deny_pass
      positive_verified_actor
      discriminating_control_without_identity_requirement
      missing_context
      expired_context
      unsupported_verification_method
      required_scope_missing
      fake_identity_metadata_in_arguments
      caller_supplied_identity_is_stripped_before_relay
      caller_override_of_principal
      truncated_actor_payload
      trailing_json_actor_payload
      actor_expires_while_approval_pending
      multiple_audiences_where_exactly_one_is_required
      gap_probe_wrong_audience_is_not_enforced
    )
    for sub in "${H52_REQUIRED_SUBTESTS[@]}"; do
      if ! grep -q -- "--- PASS: TestVerifiedActorBackendObserver/${sub} (" "$ART/test.log"; then
        echo "error: TestVerifiedActorBackendObserver: the harness floor was not met: no PASS line for subtest ${sub}" >&2
        STATUS=1
      fi
    done
    sub_pass="$(grep -c -- '--- PASS: TestVerifiedActorBackendObserver/' "$ART/test.log" || true)"
    if [ "${sub_pass:-0}" -lt 20 ]; then
      echo "error: TestVerifiedActorBackendObserver: the harness floor was not met: ${sub_pass:-0} subtest PASS line(s), floor is 20" >&2
      STATUS=1
    fi
    if [ "$STATUS" -eq 0 ]; then
      echo "subtests passed: $sub_pass"
    fi
  fi
fi

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

{
  echo "# H52 identity-aware harness run $TS"
  echo
  echo "- **Git:** \`$GIT_SHA\`"
  echo "- **Command:** \`H52_ARTIFACT_DIR=$ART go test ./tests/integration/ -count=1 -v -timeout 300s -run ^TestVerifiedActorBackendObserver$\`"
  echo "- **Exit status:** $STATUS"
  echo
  echo "## Observer artifacts"
  echo
  if compgen -G "$ART/*.jsonl" >/dev/null; then
    for f in "$ART"/*.jsonl; do
      echo "- \`$(basename "$f")\`: $(h52_artifact_status "$f")"
    done
  else
    echo "- no observer artifacts: incomplete (unmeasured)"
  fi
  echo
  echo "A denied scenario must produce a complete observer session with no \`tools/call\`"
  echo "record for that id. An absent, empty or incomplete artifact is a harness failure,"
  echo "not a denial."
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
