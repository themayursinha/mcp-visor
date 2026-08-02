// Package workflow derives supervised workflow status from artifacts only.
package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Task struct {
	TaskID             string   `json:"task_id"`
	InvariantIDs       []string `json:"invariant_ids"`
	SecuritySensitive  bool     `json:"security_sensitive"`
	SecurityProblem    string   `json:"security_problem"`
	RequiredBehavior   string   `json:"required_behavior"`
	FailureBehavior    string   `json:"failure_behavior"`
	AllowedPaths       []string `json:"allowed_paths"`
	ApprovalGatedPaths []string `json:"approval_gated_paths"`
	MaxAttempts        int      `json:"max_attempts"`
	RequiredCommands   []ReqCmd `json:"required_commands"`
}

// ReqCmd is a named command with fixed argv from the task contract.
type ReqCmd struct {
	Name   string   `json:"name"`
	Expect string   `json:"expect"` // pass|fail
	Argv   []string `json:"argv"`
}

type CommandRecord struct {
	Name            string    `json:"name"`
	Args            []string  `json:"args"`
	Exit            int       `json:"exit"`
	Source          string    `json:"source"`
	BaseSHA         string    `json:"base_sha"`
	HeadSHA         string    `json:"head_sha"`
	WorkspaceDigest string    `json:"workspace_digest"`
	LogPath         string    `json:"log_path,omitempty"`
	RecordedUTC     time.Time `json:"recorded_utc"`
}

type ReviewArtifact struct {
	Passed          bool     `json:"passed"`
	Findings        []string `json:"findings"`
	Reviewer        string   `json:"reviewer,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	HeadSHA         string   `json:"head_sha"`
	WorkspaceDigest string   `json:"workspace_digest"`
}

type ScopeResult struct {
	Base          string   `json:"base"`
	Changed       []string `json:"changed"`
	OutOfScope    []string `json:"out_of_scope"`
	ApprovalGated []string `json:"approval_gated"`
	Pass          bool     `json:"pass"`
	Dirty         []string `json:"dirty,omitempty"`
}

type Status string

const (
	StatusUnspecified       Status = "UNSPECIFIED"
	StatusSpecified         Status = "SPECIFIED"
	StatusFailureReproduced Status = "FAILURE_REPRODUCED"
	StatusTargetVerified    Status = "TARGET_VERIFIED"
	StatusHarnessVerified   Status = "HARNESS_VERIFIED"
	StatusSecurityReviewed  Status = "SECURITY_REVIEWED"
	StatusBlocked           Status = "BLOCKED"
)

type Report struct {
	TaskID           string          `json:"task_id"`
	InvariantIDs     []string        `json:"invariant_ids"`
	BaseSHA          string          `json:"base_sha"`
	HeadSHA          string          `json:"head_sha"`
	WorkspaceDigest  string          `json:"workspace_digest"`
	WorktreeDirty    bool            `json:"worktree_dirty"`
	DerivedStatus    Status          `json:"derived_status"`
	Reasons          []string        `json:"reasons"`
	Scope            ScopeResult     `json:"scope"`
	Commands         []CommandRecord `json:"commands"`
	Review           *ReviewArtifact `json:"review,omitempty"`
	EvidenceEditable bool            `json:"evidence_editable"`
	Notes            []string        `json:"notes"`
	GeneratedUTC     time.Time       `json:"generated_utc"`
}

func DefaultApprovalGated() []string {
	return []string{"*_test.go", "harness/invariants.md", "go.mod", "go.sum", "README.md", "SECURITY.md", ".github/workflows/*", ".goreleaser.yaml", ".goreleaser.yml"}
}

func LoadTask(path string) (*Task, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Task
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse task: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, errors.New("parse task: trailing JSON value")
		}
		return nil, fmt.Errorf("parse task trailing data: %w", err)
	}
	if err := ValidateTask(&t); err != nil {
		return nil, err
	}
	t.ApprovalGatedPaths = uniq(append(DefaultApprovalGated(), t.ApprovalGatedPaths...))
	return &t, nil
}

func ValidateTask(t *Task) error {
	var e []string
	if strings.TrimSpace(t.TaskID) == "" {
		e = append(e, "task_id required")
	} else if !validTaskID(t.TaskID) {
		e = append(e, "task_id must contain only ASCII letters, digits, '.', '-', or '_'")
	}
	if len(clean(t.InvariantIDs)) == 0 {
		e = append(e, "invariant_ids must be non-empty")
	}
	if len(clean(t.AllowedPaths)) == 0 {
		e = append(e, "allowed_paths must be non-empty")
	}
	if t.MaxAttempts < 1 {
		e = append(e, "max_attempts must be >= 1")
	}
	if len(t.RequiredCommands) == 0 {
		e = append(e, "required_commands must be non-empty")
	}
	seen := map[string]struct{}{}
	hasHarnessPass := false
	hasTargetPass := false
	hasRedFail := false
	for i := range t.RequiredCommands {
		c := &t.RequiredCommands[i]
		c.Name = strings.TrimSpace(c.Name)
		c.Expect = strings.ToLower(strings.TrimSpace(c.Expect))
		if c.Name == "" {
			e = append(e, fmt.Sprintf("required_commands[%d].name required", i))
		}
		if _, ok := seen[c.Name]; ok {
			e = append(e, "duplicate command name: "+c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.Expect != "pass" && c.Expect != "fail" {
			e = append(e, fmt.Sprintf("required_commands[%d].expect must be pass|fail", i))
		}
		if len(c.Argv) == 0 {
			e = append(e, fmt.Sprintf("required_commands[%d].argv must be non-empty", i))
		}
		for j, a := range c.Argv {
			if strings.TrimSpace(a) == "" {
				e = append(e, fmt.Sprintf("required_commands[%d].argv[%d] empty", i, j))
			}
		}
		if c.Name == "harness" && c.Expect == "pass" {
			hasHarnessPass = true
		}
		if c.Name != "harness" && c.Expect == "pass" {
			hasTargetPass = true
		}
		if c.Expect == "fail" {
			hasRedFail = true
		}
	}
	if !hasHarnessPass {
		e = append(e, "required_commands must include harness with expect=pass")
	}
	if !hasTargetPass {
		e = append(e, "required_commands must include a non-harness expect=pass target")
	}
	if t.SecuritySensitive && !hasRedFail {
		e = append(e, "security_sensitive tasks require at least one expect=fail command")
	}
	for _, f := range []struct{ v, n string }{
		{t.SecurityProblem, "security_problem"},
		{t.RequiredBehavior, "required_behavior"},
		{t.FailureBehavior, "failure_behavior"},
	} {
		if strings.TrimSpace(f.v) == "" {
			e = append(e, f.n+" required")
		}
	}
	for i := range t.RequiredCommands {
		if hit := argvTouchesExcludedLocalState(t.RequiredCommands[i].Argv); hit != "" {
			e = append(e, fmt.Sprintf("required_commands[%d].argv must not depend on excluded local-state path %q", i, hit))
		}
	}
	if len(e) > 0 {
		return errors.New(strings.Join(e, "; "))
	}
	return nil
}

// argvTouchesExcludedLocalState returns a path-like argv token under trees that
// are deliberately unbound from snapshot/scope (generated evidence + nested worktrees).
func argvTouchesExcludedLocalState(argv []string) string {
	for _, raw := range argv {
		a := filepath.ToSlash(strings.TrimSpace(raw))
		if a == "" {
			continue
		}
		a = strings.TrimPrefix(a, "./")
		switch {
		case a == "evidence/workflow", strings.HasPrefix(a, "evidence/workflow/"),
			a == "evidence/harness", strings.HasPrefix(a, "evidence/harness/"),
			a == ".worktrees", strings.HasPrefix(a, ".worktrees/"):
			return a
		}
	}
	return ""
}

func validTaskID(s string) bool {
	if s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func clean(ss []string) []string {
	var o []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			o = append(o, s)
		}
	}
	return o
}

func LookupCommand(t *Task, name string) (*ReqCmd, error) {
	for i := range t.RequiredCommands {
		if t.RequiredCommands[i].Name == name {
			return &t.RequiredCommands[i], nil
		}
	}
	return nil, fmt.Errorf("unknown command name %q (must be defined in task required_commands)", name)
}

func EvidenceDir(root, taskID string) string {
	return filepath.Join(root, "evidence", "workflow", taskID)
}

func commandsPath(root, taskID string) string {
	return filepath.Join(EvidenceDir(root, taskID), "commands.jsonl")
}

func LoadCommands(root, taskID string) ([]CommandRecord, error) {
	b, err := os.ReadFile(commandsPath(root, taskID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []CommandRecord
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r CommandRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, err
		}
		if r.Source != "executed" {
			r.Source = "invalid"
		}
		out = append(out, r)
	}
	return out, nil
}

// Snapshot captures immutable-enough repo identity for binding evidence.
type Snapshot struct {
	BaseSHA         string
	HeadSHA         string
	WorkspaceDigest string
}

func CurrentSnapshot(root, base string, t *Task) (Snapshot, error) {
	if t == nil {
		return Snapshot{}, errors.New("task required for snapshot")
	}
	baseSHA, err := ResolveBase(root, base)
	if err != nil {
		return Snapshot{}, err
	}
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil {
		return Snapshot{}, err
	}
	workspace, err := WorkspaceDigest(root)
	if err != nil {
		return Snapshot{}, err
	}
	contract, err := json.Marshal(t)
	if err != nil {
		return Snapshot{}, fmt.Errorf("marshal task contract: %w", err)
	}
	h := sha256.New()
	fmt.Fprintf(h, "workspace:%s\n", workspace)
	fmt.Fprintf(h, "task:%x\n", sha256.Sum256(contract))
	return Snapshot{BaseSHA: baseSHA, HeadSHA: head, WorkspaceDigest: hex.EncodeToString(h.Sum(nil))}, nil
}

// WorkspaceDigest hashes repository content, excluding generated evidence and nested worktrees.
func WorkspaceDigest(root string) (string, error) {
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	paths := map[string]struct{}{}
	addNUL := func(s string) {
		for _, p := range strings.Split(s, "\x00") {
			p = filepath.ToSlash(p)
			if p != "" && !skipLocalState(p) {
				paths[p] = struct{}{}
			}
		}
	}
	if s, err := git(root, "ls-files", "-c", "-z"); err == nil {
		addNUL(s)
	} else {
		return "", err
	}
	if s, err := git(root, "ls-files", "-o", "--exclude-standard", "-z"); err == nil {
		addNUL(s)
	} else {
		return "", err
	}
	// Commands may read gitignored files; bind them too, except self-generated evidence.
	if s, err := git(root, "ls-files", "-o", "-i", "--exclude-standard", "-z"); err == nil {
		addNUL(s)
	} else {
		return "", err
	}
	// Include paths deleted in the worktree vs HEAD.
	if s, err := git(root, "diff", "--name-only", "--diff-filter=D", "-z", "HEAD"); err == nil {
		addNUL(s)
	} else {
		return "", err
	}
	var list []string
	for p := range paths {
		list = append(list, p)
	}
	sort.Strings(list)

	h := sha256.New()
	writeRecord := func(fields ...string) {
		var buf [binary.MaxVarintLen64]byte
		writeLength := func(n int) {
			used := binary.PutUvarint(buf[:], uint64(n))
			_, _ = h.Write(buf[:used])
		}
		writeLength(len(fields))
		for _, field := range fields {
			writeLength(len(field))
			_, _ = h.Write([]byte(field))
		}
	}
	writeRecord("head", head)
	for _, p := range list {
		full := filepath.Join(root, filepath.FromSlash(p))
		fi, err := os.Lstat(full)
		if err != nil {
			writeRecord("D", p)
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			tgt, _ := os.Readlink(full)
			writeRecord("L", p, tgt)
			continue
		}
		if fi.IsDir() {
			if _, err := os.Lstat(filepath.Join(full, ".git")); err == nil {
				return "", fmt.Errorf("embedded repository is not supported: %s", p)
			} else if !os.IsNotExist(err) {
				return "", fmt.Errorf("inspect embedded repository marker %s: %w", p, err)
			}
		}
		if !fi.Mode().IsRegular() {
			writeRecord("X", p, fi.Mode().String())
			continue
		}
		sum, err := hashFile(full)
		if err != nil {
			return "", err
		}
		writeRecord("F", p, fmt.Sprintf("%04o", fi.Mode().Perm()), sum, fmt.Sprintf("%d", fi.Size()))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func skipLocalState(p string) bool {
	p = filepath.ToSlash(p)
	switch {
	case p == ".worktrees", strings.HasPrefix(p, ".worktrees/"):
		return true
	case p == "evidence/workflow", strings.HasPrefix(p, "evidence/workflow/"):
		return true
	case p == "evidence/harness", strings.HasPrefix(p, "evidence/harness/"):
		return true
	default:
		return false
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RunNamedCommand executes the task-defined argv for name. No caller argv override.
func RunNamedCommand(root string, t *Task, name, base string) (CommandRecord, error) {
	req, err := LookupCommand(t, name)
	if err != nil {
		return CommandRecord{}, err
	}
	snap, err := CurrentSnapshot(root, base, t)
	if err != nil {
		return CommandRecord{}, err
	}
	dir := EvidenceDir(root, t.TaskID)
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return CommandRecord{}, err
	}
	prefix := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + sanitize(name) + "-"
	f, err := os.CreateTemp(logDir, prefix+"*.log")
	if err != nil {
		return CommandRecord{}, err
	}
	logPath := f.Name()
	defer f.Close()

	args := append([]string(nil), req.Argv...)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = root
	cmd.Stdout = io.MultiWriter(f, os.Stdout)
	cmd.Stderr = io.MultiWriter(f, os.Stderr)
	runErr := cmd.Run()
	exit := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			return CommandRecord{}, runErr
		}
	}
	rec := CommandRecord{
		Name: name, Args: args, Exit: exit, Source: "executed",
		BaseSHA: snap.BaseSHA, HeadSHA: snap.HeadSHA, WorkspaceDigest: snap.WorkspaceDigest,
		LogPath: logPath, RecordedUTC: time.Now().UTC(),
	}
	line, _ := json.Marshal(rec)
	out, err := os.OpenFile(commandsPath(root, t.TaskID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return rec, err
	}
	defer out.Close()
	_, err = out.Write(append(line, '\n'))
	return rec, err
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "cmd"
	}
	return b.String()
}

func git(root string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimRight(stdout.String(), "\r\n"), nil
}

func ResolveBase(root, base string) (string, error) {
	if strings.TrimSpace(base) != "" {
		return git(root, "rev-parse", base)
	}
	if out, err := git(root, "merge-base", "HEAD", "origin/main"); err == nil && out != "" {
		return out, nil
	}
	return "", errors.New("cannot resolve default base: origin/main is unavailable; pass -base explicitly")
}

func CheckScope(root string, t *Task, base string) (ScopeResult, error) {
	baseSHA, err := ResolveBase(root, base)
	if err != nil {
		return ScopeResult{}, err
	}
	changed := map[string]struct{}{}
	addPath := func(p string) {
		if p != "" {
			changed[filepath.ToSlash(p)] = struct{}{}
		}
	}
	addNameStatusZ := func(s string) error {
		parts := strings.Split(s, "\x00")
		for i := 0; i < len(parts); {
			if parts[i] == "" {
				i++
				continue
			}
			status := parts[i]
			i++
			if i >= len(parts) || parts[i] == "" {
				return errors.New("malformed git --name-status -z output")
			}
			addPath(parts[i])
			i++
			if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
				if i >= len(parts) || parts[i] == "" {
					return errors.New("malformed git rename/copy output")
				}
				addPath(parts[i])
				i++
			}
		}
		return nil
	}
	addNULPaths := func(dst map[string]struct{}, s string) {
		for _, p := range strings.Split(s, "\x00") {
			if p != "" {
				dst[filepath.ToSlash(p)] = struct{}{}
			}
		}
	}

	s, err := git(root, "diff", "--name-status", "-z", baseSHA)
	if err != nil {
		return ScopeResult{}, err
	}
	if err := addNameStatusZ(s); err != nil {
		return ScopeResult{}, err
	}
	s, err = git(root, "ls-files", "-o", "--exclude-standard", "-z")
	if err != nil {
		return ScopeResult{}, err
	}
	addNULPaths(changed, s)
	s, err = git(root, "ls-files", "-o", "-i", "--exclude-standard", "-z")
	if err != nil {
		return ScopeResult{}, err
	}
	addNULPaths(changed, s)

	dirtySet := map[string]struct{}{}
	s, err = git(root, "diff", "--name-only", "-z", "HEAD")
	if err != nil {
		return ScopeResult{}, err
	}
	addNULPaths(dirtySet, s)
	s, err = git(root, "ls-files", "-o", "--exclude-standard", "-z")
	if err != nil {
		return ScopeResult{}, err
	}
	addNULPaths(dirtySet, s)
	var dirty []string
	for p := range dirtySet {
		dirty = append(dirty, p)
	}
	var list, oos, gated []string
	for p := range changed {
		if skipLocalState(p) {
			continue
		}
		list = append(list, p)
		if !pathAllowed(p, t.AllowedPaths) {
			oos = append(oos, p)
		}
		if pathGated(p, t.ApprovalGatedPaths) {
			gated = append(gated, p)
		}
		full := filepath.Join(root, p)
		if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(full)
			if err != nil {
				oos = append(oos, p+"->SYMLINK_UNRESOLVED")
				continue
			}
			rel, err := filepath.Rel(root, target)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				oos = append(oos, p+"->SYMLINK_ESCAPE")
			}
		}
	}
	sort.Strings(list)
	return ScopeResult{Base: baseSHA, Changed: list, OutOfScope: uniq(oos), ApprovalGated: uniq(gated), Pass: len(oos) == 0, Dirty: uniq(dirty)}, nil
}

func pathAllowed(p string, allowed []string) bool {
	p = filepath.ToSlash(p)
	for _, a := range allowed {
		a = strings.TrimSuffix(filepath.ToSlash(strings.TrimSpace(a)), "/")
		if a != "" && (p == a || strings.HasPrefix(p, a+"/")) {
			return true
		}
	}
	return false
}

func pathGated(p string, patterns []string) bool {
	p = filepath.ToSlash(p)
	base := filepath.Base(p)
	for _, pat := range patterns {
		pat = filepath.ToSlash(strings.TrimSpace(pat))
		switch {
		case pat == "":
		case strings.HasSuffix(pat, "/*"):
			pre := strings.TrimSuffix(pat, "/*")
			if p == pre || strings.HasPrefix(p, pre+"/") {
				return true
			}
		case strings.Contains(pat, "*"):
			if ok, _ := filepath.Match(pat, base); ok {
				return true
			}
			if ok, _ := filepath.Match(pat, p); ok {
				return true
			}
		case p == pat || base == pat:
			return true
		}
	}
	return false
}

func uniq(ss []string) []string {
	m := map[string]struct{}{}
	var o []string
	for _, s := range ss {
		if _, ok := m[s]; !ok {
			m[s] = struct{}{}
			o = append(o, s)
		}
	}
	sort.Strings(o)
	return o
}

func argvEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isTargetPassCmd(t *Task, name string) bool {
	for _, c := range t.RequiredCommands {
		if c.Name == name && c.Expect == "pass" && c.Name != "harness" {
			return true
		}
	}
	return false
}

func isRedFailCmd(t *Task, name string) bool {
	for _, c := range t.RequiredCommands {
		if c.Name == name && c.Expect == "fail" {
			return true
		}
	}
	return false
}

func countTargetAttempts(t *Task, cmds []CommandRecord) int {
	// max_attempts is per required pass-target name, not total executions.
	per := map[string]int{}
	max := 0
	for _, c := range cmds {
		if c.Source != "executed" || !isTargetPassCmd(t, c.Name) {
			continue
		}
		per[c.Name]++
		if per[c.Name] > max {
			max = per[c.Name]
		}
	}
	return max
}

func lastMatching(t *Task, cmds []CommandRecord, name string, requirePass *bool) (int, *CommandRecord) {
	req, err := LookupCommand(t, name)
	if err != nil {
		return -1, nil
	}
	for i := len(cmds) - 1; i >= 0; i-- {
		c := cmds[i]
		if c.Name != name || c.Source != "executed" {
			continue
		}
		if !argvEqual(c.Args, req.Argv) {
			continue
		}
		if requirePass != nil {
			ok := c.Exit == 0
			if *requirePass != ok {
				return -1, nil
			}
		}
		cp := c
		return i, &cp
	}
	return -1, nil
}

// DeriveStatus computes status from artifacts + current snapshot binding.
func DeriveStatus(t *Task, cmds []CommandRecord, scope ScopeResult, review *ReviewArtifact, snap Snapshot) (Status, []string) {
	if err := ValidateTask(t); err != nil {
		return StatusUnspecified, []string{"invalid_task: " + err.Error()}
	}
	var reasons []string
	for _, c := range cmds {
		if c.Source != "executed" {
			return StatusBlocked, []string{"invalid_command_record:" + c.Name}
		}
		// reject records whose argv does not match the contract
		if req, err := LookupCommand(t, c.Name); err == nil {
			if !argvEqual(c.Args, req.Argv) {
				return StatusBlocked, []string{"argv_mismatch:" + c.Name}
			}
		}
	}

	attempts := countTargetAttempts(t, cmds)
	if attempts > t.MaxAttempts {
		return StatusBlocked, []string{fmt.Sprintf("max_attempts_exceeded:%d>%d", attempts, t.MaxAttempts)}
	}

	st := StatusSpecified
	reasons = append(reasons, "valid_task_contract")

	// RED may use an earlier snapshot; must use contract argv and precede GREEN.
	redIdx := -1
	if t.SecuritySensitive {
		for i, c := range cmds {
			if c.Source != "executed" || !isRedFailCmd(t, c.Name) || c.Exit == 0 {
				continue
			}
			if req, err := LookupCommand(t, c.Name); err != nil || !argvEqual(c.Args, req.Argv) {
				continue
			}
			redIdx = i
			break
		}
		if redIdx >= 0 {
			st = StatusFailureReproduced
			reasons = append(reasons, "red_failure_recorded")
		} else {
			reasons = append(reasons, "red_failure_missing")
		}
	}

	// Targets: must match current workspace digest; all pass-expect non-harness
	targetOK := scope.Pass
	if !scope.Pass {
		reasons = append(reasons, "scope_not_pass")
	}
	if t.SecuritySensitive && redIdx < 0 {
		targetOK = false
	}

	var lastTargetIdx = -1
	for _, r := range t.RequiredCommands {
		if r.Name == "harness" || r.Expect != "pass" {
			continue
		}
		idx, c := lastMatching(t, cmds, r.Name, boolPtr(true))
		if c == nil {
			targetOK = false
			reasons = append(reasons, "required_pass_missing_or_failed:"+r.Name)
			continue
		}
		if c.WorkspaceDigest != snap.WorkspaceDigest {
			targetOK = false
			reasons = append(reasons, "target_snapshot_mismatch:"+r.Name)
			continue
		}
		if c.BaseSHA != snap.BaseSHA {
			targetOK = false
			reasons = append(reasons, "target_base_mismatch:"+r.Name)
			continue
		}
		if t.SecuritySensitive && redIdx >= 0 && idx <= redIdx {
			targetOK = false
			reasons = append(reasons, "red_must_precede_green")
			continue
		}
		if idx > lastTargetIdx {
			lastTargetIdx = idx
		}
	}

	if targetOK && lastTargetIdx >= 0 {
		st = StatusTargetVerified
		reasons = append(reasons, "scope_and_targets_pass")
	}

	// Harness: current digest, after latest successful target
	if st == StatusTargetVerified {
		hIdx, h := lastMatching(t, cmds, "harness", boolPtr(true))
		switch {
		case h == nil:
			// failed or missing
			if _, hf := lastMatching(t, cmds, "harness", boolPtr(false)); hf != nil {
				reasons = append(reasons, "harness_failed")
			} else {
				reasons = append(reasons, "harness_missing")
			}
		case h.WorkspaceDigest != snap.WorkspaceDigest:
			reasons = append(reasons, "harness_snapshot_mismatch")
		case h.BaseSHA != snap.BaseSHA:
			reasons = append(reasons, "harness_base_mismatch")
		case hIdx <= lastTargetIdx:
			reasons = append(reasons, "harness_must_follow_target")
		default:
			st = StatusHarnessVerified
			reasons = append(reasons, "harness_pass")
		}
	}

	if review != nil && review.Passed {
		if st != StatusHarnessVerified {
			reasons = append(reasons, "review_ignored_gates_not_met")
		} else if review.HeadSHA != snap.HeadSHA || review.WorkspaceDigest != snap.WorkspaceDigest {
			// Stay at HARNESS_VERIFIED; do not promote a stale review.
			reasons = append(reasons, "review_snapshot_mismatch")
		} else {
			st = StatusSecurityReviewed
			reasons = append(reasons, "review_pass")
		}
	}
	return st, reasons
}

func boolPtr(v bool) *bool { return &v }

func BuildReport(root string, t *Task, base string, review *ReviewArtifact) (*Report, error) {
	snap, err := CurrentSnapshot(root, base, t)
	if err != nil {
		return nil, err
	}
	scope, err := CheckScope(root, t, snap.BaseSHA)
	if err != nil {
		return nil, err
	}
	cmds, err := LoadCommands(root, t.TaskID)
	if err != nil {
		return nil, err
	}
	st, reasons := DeriveStatus(t, cmds, scope, review, snap)
	return &Report{
		TaskID: t.TaskID, InvariantIDs: t.InvariantIDs,
		BaseSHA: snap.BaseSHA, HeadSHA: snap.HeadSHA, WorkspaceDigest: snap.WorkspaceDigest,
		WorktreeDirty: len(scope.Dirty) > 0, DerivedStatus: st, Reasons: reasons, Scope: scope,
		Commands: cmds, Review: review, EvidenceEditable: true, GeneratedUTC: time.Now().UTC(),
		Notes: []string{
			"local evidence/workflow is editable and not tamper-proof",
			"CI-generated evidence is the planned stronger merge gate",
			"model prose cannot override command results",
			"Mayur merge/release approval is outside this tool",
			"command argv is bound by the task contract",
			"GREEN/harness/review evidence is bound to base SHA and workspace digest",
			"max_attempts is counted per pass-target name",
		},
	}, nil
}

func LoadReview(root, path string) (*ReviewArtifact, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if err := ValidateArtifactPath(root, path, "review"); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r ReviewArtifact
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ValidateArtifactPath ensures generated or consumed evidence cannot silently
// invalidate the workspace snapshot it describes.
func ValidateArtifactPath(root, path, kind string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s artifact path required", kind)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return fmt.Errorf("resolve repository root symlinks: %w", err)
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", kind, err)
	}
	pathReal, err := resolveWithMissingLeaf(pathAbs)
	if err != nil {
		return fmt.Errorf("resolve %s path symlinks: %w", kind, err)
	}
	rel, err := filepath.Rel(rootReal, pathReal)
	if err != nil {
		return fmt.Errorf("compare %s path to repository: %w", kind, err)
	}
	rel = filepath.ToSlash(rel)
	inside := rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
	underEvidence := rel == "evidence" || strings.HasPrefix(rel, "evidence/")
	if inside && !underEvidence {
		return fmt.Errorf("%s artifact inside repository must be stored under evidence/ or outside the repository", kind)
	}
	return nil
}

func resolveWithMissingLeaf(path string) (string, error) {
	current := filepath.Clean(path)
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if fi, statErr := os.Lstat(current); statErr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", err
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

// ParseMinStatus accepts only progression statuses usable with verify -min.
func ParseMinStatus(s string) (Status, error) {
	switch Status(strings.TrimSpace(s)) {
	case StatusSpecified, StatusFailureReproduced, StatusTargetVerified, StatusHarnessVerified, StatusSecurityReviewed:
		return Status(strings.TrimSpace(s)), nil
	case StatusBlocked, StatusUnspecified:
		return "", fmt.Errorf("status %q is not a valid verify -min progression status", s)
	default:
		return "", fmt.Errorf("unknown status %q", s)
	}
}

// ParseStatus accepts any known workflow status label.
func ParseStatus(s string) (Status, error) {
	switch Status(strings.TrimSpace(s)) {
	case StatusUnspecified, StatusSpecified, StatusFailureReproduced, StatusTargetVerified,
		StatusHarnessVerified, StatusSecurityReviewed, StatusBlocked:
		return Status(strings.TrimSpace(s)), nil
	default:
		return "", fmt.Errorf("unknown status %q", s)
	}
}

func StatusRank(s Status) int {
	switch s {
	case StatusSpecified:
		return 1
	case StatusFailureReproduced:
		return 2
	case StatusTargetVerified:
		return 3
	case StatusHarnessVerified:
		return 4
	case StatusSecurityReviewed:
		return 5
	default:
		return 0
	}
}

func WriteReportJSON(path string, r *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".report-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
