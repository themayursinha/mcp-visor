#!/usr/bin/env bash
# Regression matrix for scripts/check-staged-gofmt and the hook's module guard.
#
# The staged-blob arm has one job: catch a commit whose staged Go blob is not
# gofmt-clean even though the file on disk is. Review found the same shape of hole
# four times behind four different oracles (a --diff-filter list, a hidden
# producer exit status, a missing NUL delimiter, and finally `git diff` itself,
# which cannot see a path carrying the skip-worktree or assume-unchanged bit). The
# oracle is now the index, so the cases below include the two flag states that
# used to pass silently.
#
# Each case builds a throwaway repository, stages a state, and asserts the exit
# code of scripts/check-staged-gofmt or of scripts/pre-commit.
# Run: bash scripts/tests/check-staged-gofmt_test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../check-staged-gofmt"

if [ ! -f "$SCRIPT" ]; then
  echo "error: $SCRIPT not found" >&2
  exit 1
fi

UNFORMATTED='package probe

func Bad() {
var x int
_ = x
}
'
FORMATTED='package probe

func Bad() {
	var x int
	_ = x
}
'

pass=0
fail=0

new_repo() {
  local dir
  dir="$(mktemp -d)"
  mkdir -p "$dir/scripts"
  cp "$SCRIPT" "$dir/scripts/check-staged-gofmt"
  git -C "$dir" init -q
  git -C "$dir" -c user.email=t@example.com -c user.name=t commit -q --allow-empty -m init
  printf '%s' "$dir"
}

run_check() {
  local dir="$1"
  local out rc
  out="$(cd "$dir" && bash scripts/check-staged-gofmt 2>&1)"
  rc=$?
  printf '%s\n%s' "$rc" "$out"
}

expect() { # label expected_rc dir output
  local label="$1" want="$2" dir="$3" got="$4"
  local rc="${got%%$'\n'*}"
  if [ "$rc" = "$want" ]; then
    echo "OK   $label (exit $rc)"
    pass=$((pass + 1))
  else
    echo "FAIL $label (expected $want, got $rc)"
    printf '%s\n' "${got#*$'\n'}" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
  rm -rf "$dir"
}

echo "== the commit's own content is checked, whatever the index flags say =="

d="$(new_repo)"
printf '%s' "$UNFORMATTED" >"$d/a.go"
git -C "$d" add a.go
printf '%s' "$FORMATTED" >"$d/a.go"
expect "modified file: staged unformatted, worktree formatted" 1 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$UNFORMATTED" >"$d/new.go"
git -C "$d" add new.go
printf '%s' "$FORMATTED" >"$d/new.go"
expect "new file: staged unformatted, worktree formatted" 1 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/original.go"
git -C "$d" add original.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "add original"
git -C "$d" mv original.go renamed.go
printf '%s' "$UNFORMATTED" >"$d/renamed.go"
git -C "$d" add renamed.go
printf '%s' "$FORMATTED" >"$d/renamed.go"
expect "rename: staged new path unformatted, worktree formatted" 1 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf 'package probe\n\nfunc Bad( {\n' >"$d/broken.go"
git -C "$d" add broken.go
printf '%s' "$FORMATTED" >"$d/broken.go"
expect "staged blob is not parsable Go" 1 "$d" "$(run_check "$d")"

# The two states below used to pass silently: `git diff`, which was the arm's
# only oracle, cannot see a path that carries either bit.
d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/hidden.go"
git -C "$d" add hidden.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "add hidden"
printf '%s' "$UNFORMATTED" >"$d/hidden.go"
git -C "$d" add hidden.go
git -C "$d" update-index --assume-unchanged hidden.go
diff_seen="$(git -C "$d" diff --name-only -- '*.go' | wc -l)"
expect "staged unformatted blob hidden by the assume-unchanged bit (git diff saw $diff_seen paths)" 1 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/sparse-stage.go"
git -C "$d" add sparse-stage.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "add sparse-stage"
printf '%s' "$UNFORMATTED" >"$d/sparse-stage.go"
git -C "$d" add sparse-stage.go
git -C "$d" update-index --skip-worktree sparse-stage.go
diff_seen="$(git -C "$d" diff --name-only -- '*.go' | wc -l)"
expect "staged unformatted blob hidden by the skip-worktree bit (git diff saw $diff_seen paths)" 1 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/linktarget.go"
ln -s linktarget.go "$d/link.go"
git -C "$d" add link.go
rm -f "$d/link.go"
ln -s othertarget.go "$d/link.go"
expect "staged symlink retargeted after staging" 1 "$d" "$(run_check "$d")"

echo "== the hook's module guard (index blob vs working file) =="

unset HERMES_DELEGATED_CHILD_CONTEXT
export PATH="/usr/local/go/bin:${PATH}"

new_go_repo() {
  local dir
  dir="$(mktemp -d)"
  mkdir -p "$dir/scripts"
  cp "$HERE/../pre-commit" "$dir/scripts/pre-commit"
  cp "$HERE/../check-gofmt" "$dir/scripts/check-gofmt"
  cp "$HERE/../check-staged-gofmt" "$dir/scripts/check-staged-gofmt"
  cp "$HERE/../check-sensitive-content" "$dir/scripts/check-sensitive-content"
  printf 'module probe\n\ngo 1.26.8\n' >"$dir/go.mod"
  printf 'package main\n\nfunc main() {}\n' >"$dir/main.go"
  git -C "$dir" init -q
  printf '%s' "$dir"
}

run_hook_case() { # label dir expect_flag
  local label="$1" dir="$2" flag="$3"
  local out rc
  if [ "$flag" = "1" ]; then
    # The bit that hides the state from `git diff`; the guard must not care.
    git -C "$dir" update-index --skip-worktree go.mod
  fi
  out="$(cd "$dir" && bash scripts/pre-commit 2>&1)"
  rc=$?
  local diff_seen
  diff_seen="$(git -C "$dir" diff --name-only -- go.mod | wc -l)"
  if [ "$rc" = "1" ] && printf '%s' "$out" | grep -q "staged go.mod differs from the working tree"; then
    echo "OK   $label (exit 1; git diff saw $diff_seen paths)"
    pass=$((pass + 1))
  else
    echo "FAIL $label (exit $rc; git diff saw $diff_seen paths)"
    printf '%s\n' "$out" | tail -4 | sed 's/^/       /'
    fail=$((fail + 1))
  fi
  rm -rf "$dir"
}

d="$(new_go_repo)"
git -C "$d" add go.mod main.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "seed"
printf 'module probe\n\ngo 1.26.8\n\n' >"$d/go.mod"
run_hook_case "hook refuses a staged go.mod that differs from the working tree" "$d" 0

d="$(new_go_repo)"
git -C "$d" add go.mod main.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "seed"
printf 'module probe\n\ngo 1.26.8\n\n' >"$d/go.mod"
run_hook_case "hook refuses the same state when skip-worktree hides it from git diff" "$d" 1

echo "== check-gofmt: sparse checkout entries are not passed to gofmt =="

d="$(new_go_repo)"
printf 'package probe\n' >"$d/sparse.go"
git -C "$d" -c user.email=t@example.com -c user.name=t add go.mod main.go sparse.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "seed"
git -C "$d" update-index --skip-worktree sparse.go
rm -f "$d/sparse.go"
out="$(cd "$d" && bash scripts/check-gofmt 2>&1)"
rc=$?
if [ "$rc" = "0" ] && printf '%s' "$out" | grep -q "skip-worktree"; then
  echo "OK   sparse checkout passes and reports the skip-worktree count"
  pass=$((pass + 1))
else
  echo "FAIL sparse checkout blocked a clean tree (exit $rc)"
  printf '%s\n' "$out" | tail -3 | sed 's/^/       /'
  fail=$((fail + 1))
fi
rm -rf "$d"

echo "== states the arm must not block =="

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/clean.go"
git -C "$d" add clean.go
expect "clean staged file" 0 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$UNFORMATTED" >"$d/both.go"
git -C "$d" add both.go
expect "staged unformatted and worktree unformatted (the staged blob is still checked)" 1 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/target.go"
git -C "$d" add target.go
ln -s target.go "$d/link.go"
git -C "$d" add link.go
expect "staged symlink matching the working tree passes" 0 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/removed.go"
git -C "$d" add removed.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "add removed"
git -C "$d" rm -q removed.go
expect "staged deletion leaves nothing to check" 0 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/untouched.go"
git -C "$d" add untouched.go
git -C "$d" -c user.email=t@example.com -c user.name=t commit -q -m "add untouched"
expect "index populated, no staged difference" 0 "$d" "$(run_check "$d")"

echo
echo "gate matrix: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
