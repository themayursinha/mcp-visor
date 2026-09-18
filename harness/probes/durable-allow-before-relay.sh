#!/usr/bin/env bash
# H52 falsification probe: a forwarded call must not reach the backend before
# the durable allow commit path has returned.
#
# The merged harness compares the observer's receive against the allow record's
# creation timestamp. That timestamp is assigned in prepareRecord before
# appendFull, sync, and return, so a relay that happens after the timestamp
# exists but before CommitAuthorization returns still satisfies the comparison.
# This probe closes that class: it injects a delay between the full append and
# the explicit sync, writes a marker immediately after the sync succeeds (the
# first instant at which the committed record is durable), and requires the
# independent observer's receive to be no earlier than the marker (minus a
# small tolerance). A discriminating control relays the envelope inside that
# non-durable window -- i.e. while the injected delay is still running, before
# the sync -- and requires this probe's own check to fail.
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
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 not found on PATH" >&2
  exit 1
fi

h52_refuse_bad_delay() {
  local bad="$1"
  local out rc want
  set +e
  out="$(H52_PROBE_SELF_CHECK=0 H52_PROBE_COMMIT_DELAY_MS="$bad" bash "$SELF" 2>&1)"
  rc=$?
  set -e
  want="error: H52_PROBE_COMMIT_DELAY_MS must be a positive integer (got \"${bad}\")"
  if [ "$rc" -eq 0 ]; then
    echo "ERROR    self-check: H52_PROBE_COMMIT_DELAY_MS=$(printf '%q' "$bad") was not refused (exit 0)" >&2
    return 1
  fi
  if ! printf '%s\n' "$out" | grep -qF -- "$want"; then
    echo "ERROR    self-check: H52_PROBE_COMMIT_DELAY_MS=$(printf '%q' "$bad") did not print the refusal sentence" >&2
    return 1
  fi
  if printf '%s\n' "$out" | grep -q -- 'falsification probe'; then
    echo "ERROR    self-check: H52_PROBE_COMMIT_DELAY_MS=$(printf '%q' "$bad") started the probe" >&2
    return 1
  fi
  return 0
}

if [ "${H52_PROBE_SELF_CHECK-1}" != "0" ]; then
  self_ok=1
  for bad in 0 -1 abc ""; do
    if ! h52_refuse_bad_delay "$bad"; then
      self_ok=0
    fi
  done
  if [ "$self_ok" -ne 1 ]; then
    exit 1
  fi
fi

DELAY="${H52_PROBE_COMMIT_DELAY_MS-4000}"
if ! [[ "$DELAY" =~ ^[0-9]+$ ]] || [ "$DELAY" -lt 1 ]; then
  echo "error: H52_PROBE_COMMIT_DELAY_MS must be a positive integer (got \"${DELAY}\")" >&2
  exit 2
fi

h52_copy_tree() {
  local dest="$1"
  mkdir -p "$dest"
  git archive HEAD | tar -x -C "$dest"
  # git archive copies HEAD only. Overlay working-tree files so an uncommitted
  # harness fix is what the probe measures. Skip the proxy sources: Stage B
  # injects into the scratch copy of HEAD's relay loop, never into the repository.
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    case "$f" in
      internal/proxy/*) continue ;;
    esac
    if [ -f "$f" ]; then
      mkdir -p "$dest/$(dirname "$f")"
      cp -f "$f" "$dest/$f"
    elif [ -f "$dest/$f" ]; then
      rm -f "$dest/$f"
    fi
  done <<EOF
$(git diff --name-only HEAD)
$(git ls-files -o --exclude-standard)
EOF
}

h52_inject_commit_delay() {
  local tree="$1"
  local marker="$2"
  local delay="$3"
  python3 - "$tree/internal/audit/logger.go" "$marker" "$delay" <<'PY'
import json, sys

path, marker, delay = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read()
sig = "func (l *Logger) CommitAuthorization(event Event) error {"
idx = src.find(sig)
if idx < 0:
    sys.stderr.write("error: CommitAuthorization not found\n")
    sys.exit(1)
if src.find(sig, idx + 1) >= 0:
    sys.stderr.write("error: CommitAuthorization found more than once\n")
    sys.exit(1)
start = idx + len(sig) - 1
depth = 0
end = None
for i, ch in enumerate(src[start:], start):
    if ch == "{":
        depth += 1
    elif ch == "}":
        depth -= 1
        if depth == 0:
            end = i
            break
if end is None:
    sys.stderr.write("error: CommitAuthorization body not closed\n")
    sys.exit(1)
body = src[start : end + 1]
sync = (
    "\tif err := l.syncFn(); err != nil {\n"
    "\t\tl.poisoned = true\n"
    '\t\treturn fmt.Errorf("audit sync: %w", err)\n'
    "\t}\n"
)
if body.count(sync) != 1:
    sys.stderr.write("error: CommitAuthorization syncFn block not found exactly once\n")
    sys.exit(1)
insert = (
    f"\ttime.Sleep({delay} * time.Millisecond)\n"
    + sync
    + f"\t_ = os.WriteFile({json.dumps(marker)}, []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o600)\n"
)
new_body = body.replace(sync, insert, 1)
open(path, "w").write(src[:start] + new_body + src[end + 1 :])
PY
}

h52_inject_early_relay() {
  local tree="$1"
  local delay="$2"
  python3 - "$tree/internal/proxy/proxy.go" "$delay" <<'PY'
import sys

path, delay = sys.argv[1], int(sys.argv[2])
src = open(path).read()
old = "\t\tmodified, action := p.interceptAndModify(raw, client)\n"
if src.count(old) != 1:
    sys.stderr.write("error: early-relay injection site not found exactly once\n")
    sys.exit(1)
half = delay // 2
new = (
    f"\t\tgo func(b []byte) {{ time.Sleep({half} * time.Millisecond); _ = p.encodeIfNotRevoked(server.EncodeRaw, b) }}(append([]byte(nil), raw...))\n"
    + old
)
open(path, "w").write(src.replace(old, new, 1))
PY
}

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
TREE_A="$SCRATCH/treeA"
TREE_B="$SCRATCH/treeB"
ART_A="$SCRATCH/artA"
ART_B="$SCRATCH/artB"
MARK_A="$SCRATCH/commitA"
MARK_B="$SCRATCH/commitB"
mkdir -p "$ART_A" "$ART_B"

h52_copy_tree "$TREE_A"
h52_inject_commit_delay "$TREE_A" "$MARK_A" "$DELAY"
if ! (cd "$TREE_A" && go build ./... ); then
  echo "error: the injected scratch tree A does not build" >&2
  exit 1
fi

h52_copy_tree "$TREE_B"
h52_inject_commit_delay "$TREE_B" "$MARK_B" "$DELAY"
h52_inject_early_relay "$TREE_B" "$DELAY"
if ! (cd "$TREE_B" && go build ./... ); then
  echo "error: the injected scratch tree B does not build" >&2
  exit 1
fi

echo "=== H52 falsification probe: durable-allow-before-relay (delay ${DELAY}ms) ==="
echo "repo:    $ROOT"
echo "head:    $(git rev-parse HEAD)"
echo "tree A:  $TREE_A"
echo "tree B:  $TREE_B"
echo

STATUS=0
PATTERN='^TestVerifiedActorBackendObserver$/^positive_verified_actor$'
MERGED_LEAK='before the durable allow'

run_stage() {
  local tree="$1"
  local art="$2"
  local log="$3"
  set +e
  (cd "$tree" && H52_ARTIFACT_DIR="$art" go test ./tests/integration/ \
    -count=1 -v -timeout 900s \
    -run "$PATTERN") >"$log" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

RC_A="$(run_stage "$TREE_A" "$ART_A" "$SCRATCH/stageA.log")"
set +e
python3 - "$ART_A" "$MARK_A" "$SCRATCH/stageA.log" "$RC_A" A <<'PY'
import glob, hashlib, json, os, sys
from datetime import datetime, timedelta, timezone

art, marker_path, log_path, rc, stage = sys.argv[1:6]
txn = "txn-positive"
tolerance_ms = 250

def fail(msg):
    print("MISS     stage-%s: %s" % (stage, msg))
    raise SystemExit(1)

def parse_ts(s):
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)

if rc != "0":
    fail("focused scenario exited %s (want 0)" % rc)
log = open(log_path).read()
if "--- PASS: TestVerifiedActorBackendObserver/positive_verified_actor" not in log:
    fail("no PASS line for positive_verified_actor (a green exit alone is not evidence)")
if not os.path.isfile(marker_path):
    fail("commit marker missing at %s" % marker_path)
marker_raw = open(marker_path).read().strip()
try:
    marker = parse_ts(marker_raw)
except Exception as e:
    fail("unparsable marker %r: %s" % (marker_raw, e))

sessions = []
for path in sorted(glob.glob(os.path.join(art, "*.jsonl"))):
    raw = open(path, "rb").read()
    if not raw.strip():
        continue
    trimmed = raw[:-1] if raw.endswith(b"\n") else raw
    idx = trimmed.rfind(b"\n")
    if idx < 0:
        prefix, end_line = b"", trimmed
    else:
        prefix, end_line = trimmed[: idx + 1], trimmed[idx + 1 :]
    try:
        term = json.loads(end_line)
    except Exception:
        continue
    if not isinstance(term, dict) or term.get("event") != "end":
        continue
    digest = hashlib.sha256(prefix).hexdigest()
    if term.get("bytes") != len(prefix) or term.get("sha256") != digest:
        continue
    calls = []
    for line in prefix.split(b"\n"):
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            calls = None
            break
        if obj.get("record") == "call":
            calls.append(obj)
    if calls is None:
        continue
    sidecar = path[: -len(".jsonl")] + ".client.json" if path.endswith(".jsonl") else path + ".client.json"
    sessions.append((path, calls, sidecar))

if len(sessions) != 1:
    fail("want exactly one complete observer session, got %d" % len(sessions))
path, calls, sidecar = sessions[0]
if not os.path.isfile(sidecar):
    fail("client sidecar missing at %s" % sidecar)
try:
    side = json.loads(open(sidecar).read())
except Exception as e:
    fail("client sidecar is not JSON: %s" % e)
if side.get("transaction") != txn:
    fail("client sidecar transaction=%r, want %s" % (side.get("transaction"), txn))

matched = []
for rec in calls:
    raw_txn = rec.get("transaction")
    if raw_txn == txn or json.dumps(raw_txn) == json.dumps(txn):
        matched.append(rec)
    elif str(raw_txn).strip('"') == txn:
        matched.append(rec)
if not matched:
    fail("complete session has no record for %s" % txn)

deltas = []
for rec in matched:
    try:
        recv = parse_ts(rec.get("received_at", ""))
    except Exception as e:
        fail("unparsable received_at %r: %s" % (rec.get("received_at"), e))
    delta_ms = (recv - marker).total_seconds() * 1000.0
    deltas.append(delta_ms)
    if recv + timedelta(milliseconds=tolerance_ms) < marker:
        fail("%s received_at=%s marker=%s delta=%.1fms (need >= -%dms)" % (
            txn, rec.get("received_at"), marker_raw, delta_ms, tolerance_ms))

print("CAUGHT   stage-A: %s received_at - marker = %s (tolerance -%dms)" % (
    txn, ", ".join("%.1fms" % d for d in deltas), tolerance_ms))
PY
pyA=$?
set -e
if [ "$pyA" -ne 0 ]; then
  STATUS=1
fi

RC_B="$(run_stage "$TREE_B" "$ART_B" "$SCRATCH/stageB.log")"
if grep -q -- "$MERGED_LEAK" "$SCRATCH/stageB.log"; then
  echo "INFO     merged harness timestamp comparison named the leak (the backend received the call ... before the durable allow)"
else
  echo "INFO     merged harness timestamp comparison did not name the leak (the backend received the call ... before the durable allow)"
fi
set +e
python3 - "$ART_B" "$MARK_B" "$SCRATCH/stageB.log" "$RC_B" B <<'PY'
import glob, hashlib, json, os, sys
from datetime import datetime, timedelta

art, marker_path, log_path, rc, stage = sys.argv[1:6]
txn = "txn-positive"
tolerance_ms = 250

def fail(msg):
    print("MISS     control: %s" % msg)
    raise SystemExit(1)

def parse_ts(s):
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)

if not os.path.isfile(marker_path):
    fail("commit marker missing at %s" % marker_path)
marker_raw = open(marker_path).read().strip()
try:
    marker = parse_ts(marker_raw)
except Exception as e:
    fail("unparsable marker %r: %s" % (marker_raw, e))

sessions = []
for path in sorted(glob.glob(os.path.join(art, "*.jsonl"))):
    raw = open(path, "rb").read()
    if not raw.strip():
        continue
    trimmed = raw[:-1] if raw.endswith(b"\n") else raw
    idx = trimmed.rfind(b"\n")
    if idx < 0:
        prefix, end_line = b"", trimmed
    else:
        prefix, end_line = trimmed[: idx + 1], trimmed[idx + 1 :]
    try:
        term = json.loads(end_line)
    except Exception:
        continue
    if not isinstance(term, dict) or term.get("event") != "end":
        continue
    digest = hashlib.sha256(prefix).hexdigest()
    if term.get("bytes") != len(prefix) or term.get("sha256") != digest:
        continue
    calls = []
    for line in prefix.split(b"\n"):
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            calls = None
            break
        if obj.get("record") == "call":
            calls.append(obj)
    if calls is None:
        continue
    sessions.append(calls)

if not sessions:
    fail("no complete observer session in the control tree")

matched = []
for calls in sessions:
    for rec in calls:
        raw_txn = rec.get("transaction")
        if raw_txn == txn or str(raw_txn).strip('"') == txn:
            matched.append(rec)
if not matched:
    fail("no observer record for %s in the control tree" % txn)

early = []
for rec in matched:
    try:
        recv = parse_ts(rec.get("received_at", ""))
    except Exception as e:
        fail("unparsable received_at %r: %s" % (rec.get("received_at"), e))
    delta_ms = (recv - marker).total_seconds() * 1000.0
    if recv + timedelta(milliseconds=tolerance_ms) < marker:
        early.append(delta_ms)

if not early:
    deltas = []
    for rec in matched:
        recv = parse_ts(rec.get("received_at", ""))
        deltas.append((recv - marker).total_seconds() * 1000.0)
    fail("ordering check did not detect a receive earlier than marker - %dms; deltas=%s (a probe whose check cannot fail is worthless)" % (
        tolerance_ms, ", ".join("%.1fms" % d for d in deltas)))

print("CAUGHT   control: %s received_at - marker = %s (violation < -%dms)" % (
    txn, ", ".join("%.1fms" % d for d in early), tolerance_ms))
PY
pyB=$?
set -e
if [ "$pyB" -ne 0 ]; then
  STATUS=1
fi

echo
if [ "$STATUS" -ne 0 ]; then
  echo "=== durable-allow-before-relay probe FAILED: the harness does not catch a relay inside the non-durable commit window ==="
  exit 1
fi
echo "=== durable-allow-before-relay probe OK: backend receive is no earlier than the durable commit return ==="
