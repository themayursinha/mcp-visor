#!/usr/bin/env bash
# Regression matrix for scripts/check-staged-gofmt.
#
# The staged-blob arm of the pre-commit hook has one job: catch a commit whose
# staged Go blob is not gofmt-clean even though the file on disk is. That hole was
# found three times in review rounds (missing NUL delimiting, hidden producer exit
# status, dropped rename entries), so the arm now has a committed test matrix and
# enumerates index/worktree differences instead of a --diff-filter list.
#
# Each case builds a throwaway repository, stages a state, and asserts the exit
# code of scripts/check-staged-gofmt. Run: bash scripts/tests/check-staged-gofmt_test.sh
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

echo "== staged blob differs from the working tree =="

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
printf '%s' "$UNFORMATTED" >"$d/broken.go"
git -C "$d" add broken.go
printf 'package probe\n\nfunc Bad( {\n' >"$d/broken.go"
expect "staged parse error" 1 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/linktarget.go"
ln -s linktarget.go "$d/link.go"
git -C "$d" add link.go
rm -f "$d/link.go"
ln -s othertarget.go "$d/link.go"
expect "staged symlink retargeted after staging" 1 "$d" "$(run_check "$d")"

echo "== the hook's module guard (staged go.mod vs working tree) =="

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

d="$(new_go_repo)"
git -C "$d" add go.mod main.go
printf 'module probe\n\ngo 1.26.8\n\nrequire example.com/nope v0.0.0\n' >"$d/go.mod"
out="$(cd "$d" && bash scripts/pre-commit 2>&1)"
rc=$?
if printf '%s' "$out" | grep -q "staged go.mod/go.sum differ"; then
  echo "OK   hook refuses a staged go.mod that differs from the working tree (exit $rc)"
  pass=$((pass + 1))
else
  echo "FAIL hook let a stale staged go.mod through"
  printf '%s\n' "$out" | tail -4 | sed 's/^/       /'
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
expect "staged unformatted and worktree unformatted (working-tree arm owns this)" 0 "$d" "$(run_check "$d")"

d="$(new_repo)"
printf '%s' "$FORMATTED" >"$d/target.go"
git -C "$d" add target.go
ln -s target.go "$d/link.go"
git -C "$d" add link.go
expect "staged symlink named *.go is skipped" 0 "$d" "$(run_check "$d")"

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
expect "nothing staged" 0 "$d" "$(run_check "$d")"

echo
echo "staged-blob matrix: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
