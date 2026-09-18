#!/usr/bin/env bash
# H52 falsification probe: the harness must catch a denied call that was relayed
# to the backend anyway.
#
# The probe copies the tree into a scratch directory, injects the relay-on-deny
# fault into the proxy's client-to-server loop (a denied envelope is also written
# to the backend before the loop continues), and then requires every runtime-deny
# scenario to fail, on every repetition, with the harness's own named leak:
#
#   the backend received a call the gate denied
#
# A scenario that passes, or that fails as anything other than the named leak, is
# a probe failure: it means the harness cannot prove the property it publishes.
#
# The injection lives only in the scratch copy. Nothing under the repository is
# modified: no commit, no push, no tracked-file change.
#
# Run from anywhere; the script resolves the repository root itself.
set -euo pipefail

# Absolute path before cd: the self-check re-invokes this file from any cwd.
PROBE_DIR="$(cd "$(dirname "$0")" && pwd)"
SELF="$PROBE_DIR/$(basename "$0")"
ROOT="$(cd "$PROBE_DIR/../.." && pwd)"
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

# A value is canonical decimal only if it is ASCII digits with no leading zero and
# no sign. The match runs under LC_ALL=C because a UTF-8 collation range such as
# [0-9] also matches non-ASCII digits and fractions. This knob feeds Bash
# arithmetic, which parses a leading zero as octal (010 is 8, 08 is an error), so
# a non-canonical spelling silently changes the number of repetitions requested.
h52_is_canonical_decimal() {
  local LC_ALL=C
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

h52_refuse_bad_reps() {
  local bad="$1" want="$2"
  local out rc
  set +e
  out="$(H52_PROBE_SELF_CHECK=0 H52_PROBE_REPS="$bad" bash "$SELF" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "ERROR    self-check: H52_PROBE_REPS=$(printf '%q' "$bad") was not refused (exit 0)" >&2
    return 1
  fi
  if ! printf '%s\n' "$out" | grep -qF -- "$want"; then
    echo "ERROR    self-check: H52_PROBE_REPS=$(printf '%q' "$bad") did not print the refusal sentence" >&2
    return 1
  fi
  if printf '%s\n' "$out" | grep -q -- 'falsification probe'; then
    echo "ERROR    self-check: H52_PROBE_REPS=$(printf '%q' "$bad") started the probe" >&2
    return 1
  fi
  return 0
}

if [ "${H52_PROBE_SELF_CHECK-1}" != "0" ]; then
  self_ok=1
  shape='error: H52_PROBE_REPS must be a positive decimal integer without leading zeros or a sign (got '
  for bad in 0 -1 abc "" 04000 010 08 "+5" １2; do
    if ! h52_refuse_bad_reps "$bad" "${shape}\"${bad}\")"; then
      self_ok=0
    fi
  done
  if [ "$self_ok" -ne 1 ]; then
    exit 1
  fi
fi

# Unset -> 5. Set-but-empty, zero, negative, junk and any non-canonical spelling
# (leading zero, sign, non-ASCII digit) must not become "run nothing or a
# different count and still report probe OK". Bash arithmetic reads a leading zero
# as octal, so the spelling is checked here, before any scratch tree is built.
REPS="${H52_PROBE_REPS-5}"
if ! h52_is_canonical_decimal "$REPS"; then
  echo "error: H52_PROBE_REPS must be a positive decimal integer without leading zeros or a sign (got \"${REPS}\")" >&2
  exit 2
fi

DENY_LEGS=(
  expired_context
  required_scope_missing
  fake_identity_metadata_in_arguments
  caller_override_of_principal
  actor_expires_while_approval_pending
)
LEAK="the backend received a call the gate denied"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p "$SCRATCH/tree"

git archive HEAD | tar -x -C "$SCRATCH/tree"

# git archive copies HEAD only. Overlay working-tree files so an uncommitted
# harness fix is what the probe measures. Skip the proxy sources: the fault is
# injected into the scratch copy of HEAD's relay loop, never into the repository.
while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    internal/proxy/*) continue ;;
  esac
  if [ -f "$f" ]; then
    mkdir -p "$SCRATCH/tree/$(dirname "$f")"
    cp -f "$f" "$SCRATCH/tree/$f"
  elif [ -f "$SCRATCH/tree/$f" ]; then
    # A working-tree deletion is not in HEAD's archive; remove the scratch copy
    # so the probe measures the working tree rather than a HEAD residue.
    rm -f "$SCRATCH/tree/$f"
  fi
done <<EOF
$(git diff --name-only HEAD)
$(git ls-files -o --exclude-standard)
EOF

# Inject the fault at the deny branch of the client-to-server relay: the denied
# envelope is encoded to the backend before the loop continues, exactly the shape
# the class probe is meant to catch.
python3 - "$SCRATCH/tree/internal/proxy/proxy.go" <<'PY'
import sys

path = sys.argv[1]
src = open(path).read()
old = (
    '\t\tmodified, action := p.interceptAndModify(raw, client)\n'
    '\t\tif action == "denied" {\n'
    '\t\t\tcontinue\n'
    '\t\t}\n'
)
new = (
    '\t\tmodified, action := p.interceptAndModify(raw, client)\n'
    '\t\tif action == "denied" {\n'
    '\t\t\t_ = p.encodeIfNotRevoked(server.EncodeRaw, raw)\n'
    '\t\t\tcontinue\n'
    '\t\t}\n'
)
if src.count(old) != 1:
    sys.stderr.write("error: relay-on-deny injection site not found exactly once\n")
    sys.exit(1)
open(path, "w").write(src.replace(old, new, 1))
PY

if ! (cd "$SCRATCH/tree" && go build ./... ); then
  echo "error: the injected scratch tree does not build" >&2
  exit 1
fi

echo "=== H52 falsification probe: relay-on-deny (${REPS} repetitions per scenario) ==="
echo "repo:    $ROOT"
echo "head:    $(git rev-parse HEAD)"
echo "scratch: $SCRATCH/tree"
echo

STATUS=0
for leg in "${DENY_LEGS[@]}"; do
  # Anchored per level: the first element selects the test, the second the scenario.
  pattern="$(printf '^TestVerifiedActorBackendObserver$/^%s$' "$leg")"
  caught=0
  saw_pass=0
  saw_no_test=0
  miss_rep=0
  miss_rc=0
  pass_rep=0
  pass_rep_rc=0
  rc=0
  for ((rep=1; rep<=REPS; rep++)); do
    log="$SCRATCH/${leg}.${rep}.log"
    set +e
    (cd "$SCRATCH/tree" && go test ./tests/integration/ \
      -count=1 -timeout 900s \
      -run "$pattern" ) >"$log" 2>&1
    rc=$?
    set -e
    if grep -q 'no tests to run' "$log"; then
      saw_no_test=1
    fi
    if grep -q -- "$LEAK" "$log"; then
      caught=$((caught + 1))
    elif [ "$miss_rep" -eq 0 ]; then
      miss_rep=$rep
      miss_rc=$rc
    fi
    if [ "$rc" -eq 0 ]; then
      saw_pass=1
      if [ "$pass_rep" -eq 0 ]; then
        pass_rep=$rep
        pass_rep_rc=$rc
      fi
    fi
  done
  if [ "$saw_no_test" -ne 0 ]; then
    echo "ERROR    $leg: the focused leg did not select any test"
    STATUS=1
    continue
  fi
  if [ "$saw_pass" -ne 0 ] && [ "$caught" -eq 0 ]; then
    echo "MISS     $leg: the scenario passed against a relayed call (0 of $REPS caught)"
    STATUS=1
    continue
  fi
  if [ "$saw_pass" -ne 0 ] || [ "$caught" -lt "$REPS" ]; then
    if [ "$miss_rep" -ne 0 ]; then
      echo "PARTIAL  $leg: $caught of $REPS repetitions named the leak; repetition $miss_rep exited $miss_rc without naming it"
    else
      echo "PARTIAL  $leg: $caught of $REPS repetitions named the leak; repetition $pass_rep exited 0 against a relayed call"
    fi
    STATUS=1
    continue
  fi
  echo "CAUGHT   $leg: $caught of $REPS repetitions named the leak"
done

# The whole harness, not only the focused legs, must fail against the injected tree.
fullLog="$SCRATCH/harness.log"
set +e
bash "$SCRATCH/tree/harness/identity-aware.sh" >"$fullLog" 2>&1
fullRC=$?
set -e
fullCaught="$(grep -c -- "$LEAK" "$fullLog" 2>/dev/null || true)"
if [ "$fullRC" -eq 0 ]; then
  echo "MISS     full harness: exited 0 against a relayed call"
  STATUS=1
elif [ "${fullCaught:-0}" -eq 0 ]; then
  echo "PARTIAL  full harness: failed (exit $fullRC) without naming the leak"
  STATUS=1
else
  echo "CAUGHT   full harness: exit $fullRC, $fullCaught named leak(s)"
fi

echo
if [ "$STATUS" -ne 0 ]; then
  echo "=== relay-on-deny probe FAILED: the harness does not catch the class it publishes ==="
  exit 1
fi
echo "=== relay-on-deny probe OK: every runtime-deny scenario caught the relayed call on every run ==="
