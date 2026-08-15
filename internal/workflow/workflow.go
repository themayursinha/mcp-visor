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
	"strconv"
	"strings"
	"time"
)

type Task struct {
	TaskID                     string        `json:"task_id"`
	InvariantIDs               []string      `json:"invariant_ids"`
	SecuritySensitive          bool          `json:"security_sensitive"`
	SecurityProblem            string        `json:"security_problem"`
	RequiredBehavior           string        `json:"required_behavior"`
	FailureBehavior            string        `json:"failure_behavior"`
	AllowedPaths               []string      `json:"allowed_paths"`
	ApprovalGatedPaths         []string      `json:"approval_gated_paths"`
	MaxAttempts                int           `json:"max_attempts"`
	RequiredCommands           []ReqCmd      `json:"required_commands"`
	SpecRevision               int           `json:"spec_revision"`
	MaxSameFailureClassStrikes int           `json:"max_same_failure_class_strikes"`
	NonGoals                   []string      `json:"non_goals"`
	AttackClasses              []AttackClass `json:"attack_classes"`
}

// AttackClass is one machine-readable row of the frozen threat taxonomy. The
// failure_class value is the canonical class name that reviews reference in
// failure_classes[] / covered_attack_classes[] / closed_failure_classes[].
type AttackClass struct {
	ID           string `json:"id"`
	FailureClass string `json:"failure_class"`
	Expected     string `json:"expected"`
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
	// SpecSequence is the journal sequence of the current spec pass at
	// execution (ReviewArtifact.Sequence from evidence/workflow/<task>/reviews/<n>.json).
	// RED is fresh iff this equals the current spec pass's sequence. It is a
	// derived binding written by RunNamedCommand, not a wall-clock or mtime.
	SpecSequence int `json:"spec_sequence,omitempty"`
}

type ReviewArtifact struct {
	Passed               bool      `json:"passed"`
	Phase                string    `json:"phase,omitempty"` // "spec" | "implementation" (empty == implementation)
	Findings             []string  `json:"findings,omitempty"`
	FailureClasses       []string  `json:"failure_classes,omitempty"` // canonical failure classes (implementation reviews)
	SpecRevision         int       `json:"spec_revision,omitempty"`
	ContractDigest       string    `json:"contract_digest,omitempty"`
	CoveredAttackClasses []string  `json:"covered_attack_classes,omitempty"`
	Counterexamples      []string  `json:"counterexamples,omitempty"`
	ClosedFailureClasses []string  `json:"closed_failure_classes,omitempty"`
	Reviewer             string    `json:"reviewer,omitempty"`
	Notes                string    `json:"notes,omitempty"`
	HeadSHA              string    `json:"head_sha,omitempty"`
	WorkspaceDigest      string    `json:"workspace_digest,omitempty"`
	BaseSHA              string    `json:"base_sha,omitempty"`
	Sequence             int       `json:"sequence,omitempty"`
	RecordedUTC          time.Time `json:"recorded_utc,omitempty"` // informational; not used for RED freshness
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
	StatusSpecReviewed      Status = "SPEC_REVIEWED"
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
	SpecPass         bool            `json:"spec_pass"`
	ContractDigest   string          `json:"contract_digest"`
	StopLoss         string          `json:"stop_loss,omitempty"`
	EvidenceEditable bool            `json:"evidence_editable"`
	Notes            []string        `json:"notes"`
	GeneratedUTC     time.Time       `json:"generated_utc"`
}

func DefaultApprovalGated() []string {
	return []string{"*_test.go", "harness/invariants.md", "go.mod", "go.sum", "README.md", "SECURITY.md", ".github/workflows/*", ".goreleaser.yaml", ".goreleaser.yml"}
}

// ContractDigest is the canonical digest of the normalized task contract. Spec
// reviews bind to this digest plus spec_revision only (not head/base/workspace).
func ContractDigest(t *Task) (string, error) {
	contract, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("marshal task contract: %w", err)
	}
	sum := sha256.Sum256(contract)
	return hex.EncodeToString(sum[:]), nil
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
	// The spec-adversarial gate and two-strike stop-loss are MANDATORY for
	// every security-sensitive task: a task that omits spec_revision must not
	// silently bypass the spec gate. Validate the full taxonomy when the task
	// declares the regime; reject security tasks that do not declare it.
	if t.SecuritySensitive && t.SpecRevision < 1 {
		e = append(e, "security_sensitive tasks require spec_revision >= 1 (spec gate + stop-loss are mandatory)")
	}
	if specRegime(t) {
		if t.MaxSameFailureClassStrikes != 2 {
			e = append(e, "max_same_failure_class_strikes must be 2 when spec_revision >= 1")
		}
		if len(t.AttackClasses) == 0 {
			e = append(e, "attack_classes must be non-empty when spec_revision >= 1")
		}
		if len(clean(t.NonGoals)) == 0 {
			e = append(e, "non_goals must be non-empty when spec_revision >= 1")
		}
		seenClass := map[string]struct{}{}
		for i, ac := range t.AttackClasses {
			if strings.TrimSpace(ac.ID) == "" {
				e = append(e, fmt.Sprintf("attack_classes[%d].id required", i))
			}
			fc := strings.TrimSpace(ac.FailureClass)
			if fc == "" {
				e = append(e, fmt.Sprintf("attack_classes[%d].failure_class required", i))
			} else if _, dup := seenClass[fc]; dup {
				e = append(e, fmt.Sprintf("attack_classes[%d].failure_class duplicate: %s", i, fc))
			}
			seenClass[fc] = struct{}{}
			if strings.TrimSpace(ac.Expected) == "" {
				e = append(e, fmt.Sprintf("attack_classes[%d].expected required", i))
			}
		}
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
// are deliberately unbound from snapshot/scope (generated evidence only).
// Scans every token substring to catch embedded paths (e.g. sh -c "cat evidence/...").
// This is fail-closed best-effort for interpreter strings, not a full FS taint tracker.
func argvTouchesExcludedLocalState(argv []string) string {
	for _, raw := range argv {
		s := filepath.ToSlash(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		for _, prefix := range []string{"evidence/workflow", "evidence/harness"} {
			if s == prefix || strings.HasPrefix(s, prefix+"/") || strings.Contains(s, "/"+prefix+"/") || strings.Contains(s, " "+prefix) || strings.HasPrefix(s, "--input="+prefix) || strings.Contains(s, "'"+prefix) || strings.Contains(s, "\""+prefix) {
				return prefix
			}
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

// specRegime reports whether the task opts into the spec-adversarial gate and
// the two-strike stop-loss: a security-sensitive contract that declares a
// spec_revision and a machine-readable threat taxonomy.
func specRegime(t *Task) bool {
	return t.SecuritySensitive && t.SpecRevision >= 1
}

// canonicalClasses returns the canonical failure-class names declared by the
// task's attack_classes[].failure_class entries. Reviews reference these names.
func canonicalClasses(t *Task) map[string]struct{} {
	m := map[string]struct{}{}
	for _, ac := range t.AttackClasses {
		if fc := strings.TrimSpace(ac.FailureClass); fc != "" {
			m[fc] = struct{}{}
		}
	}
	return m
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
	contractDigest, err := ContractDigest(t)
	if err != nil {
		return Snapshot{}, err
	}
	h := sha256.New()
	fmt.Fprintf(h, "workspace:%s\n", workspace)
	fmt.Fprintf(h, "task:%s\n", contractDigest)
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
	// Bind untracked empty directories (git ls-files skips them without --directory).
	if s, err := git(root, "ls-files", "-o", "--exclude-standard", "--directory", "-z"); err == nil {
		addNUL(s)
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
	specSeq := 0
	if specRegime(t) {
		reviews, err := LoadReviewSequence(root, t)
		if err != nil {
			return CommandRecord{}, fmt.Errorf("review evidence: %w", err)
		}
		digest, err := ContractDigest(t)
		if err != nil {
			return CommandRecord{}, err
		}
		if cls, n, ok := stopLossClass(t, reviews, digest, t.SpecRevision); ok {
			return CommandRecord{}, fmt.Errorf("task commands rejected: same_failure_class_stop_loss:%s:%d/%d", cls, n, t.MaxSameFailureClassStrikes)
		}
		pass := currentSpecPass(reviews, digest, t.SpecRevision)
		if pass == nil {
			return CommandRecord{}, errors.New("spec_review_required: current passing spec review for contract digest + spec_revision required before task commands")
		}
		specSeq = pass.Sequence
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
		LogPath: logPath, RecordedUTC: time.Now().UTC(), SpecSequence: specSeq,
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
// reviews is the ordered review sequence (spec + implementation); legacy callers
// may pass nil when no review evidence exists.
func DeriveStatus(t *Task, cmds []CommandRecord, scope ScopeResult, review *ReviewArtifact, reviews []ReviewArtifact, snap Snapshot) (Status, []string) {
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

	// Review evidence must be structurally valid against the task taxonomy.
	for i := range reviews {
		if err := ValidateReviewArtifact(&reviews[i], t); err != nil {
			return StatusBlocked, []string{"invalid_review_evidence: " + err.Error()}
		}
	}

	// Two-strike stop-loss: evaluated before, but independently of, max_attempts.
	digest, err := ContractDigest(t)
	if err != nil {
		return StatusBlocked, []string{"contract_digest_error: " + err.Error()}
	}
	if specRegime(t) {
		if cls, n, ok := stopLossClass(t, reviews, digest, t.SpecRevision); ok {
			return StatusSpecified, []string{
				"valid_task_contract",
				fmt.Sprintf("same_failure_class_stop_loss:%s:%d/%d", cls, n, t.MaxSameFailureClassStrikes),
				"task_commands_rejected",
			}
		}
	}

	attempts := countTargetAttempts(t, cmds)
	if attempts > t.MaxAttempts {
		return StatusBlocked, []string{fmt.Sprintf("max_attempts_exceeded:%d>%d", attempts, t.MaxAttempts)}
	}

	st := StatusSpecified
	reasons = append(reasons, "valid_task_contract")

	// Spec gate: no status above SPECIFIED before a current spec pass.
	var specPass *ReviewArtifact
	if specRegime(t) {
		specPass = currentSpecPass(reviews, digest, t.SpecRevision)
		if specPass == nil {
			reasons = append(reasons, "spec_review_required")
			if latest := LatestSpecReview(reviews, digest, t.SpecRevision); latest != nil && !latest.Passed {
				reasons = append(reasons, "spec_review_latest_failed")
			}
			return st, reasons
		}
		st = StatusSpecReviewed
		reasons = append(reasons, "spec_review_pass")
	}

	// RED must use contract argv and precede GREEN. Under the spec regime a
	// reviewed closure starts a fresh RED cycle: only RED whose spec_sequence
	// matches the current spec pass's journal sequence counts (old RED is
	// invalidated). Sequence is the journal filename order, not wall-clock or
	// filesystem mtime — those are caller-controlled.
	redIdx := -1
	if t.SecuritySensitive {
		for i, c := range cmds {
			if c.Source != "executed" || !isRedFailCmd(t, c.Name) || c.Exit == 0 {
				continue
			}
			if req, err := LookupCommand(t, c.Name); err != nil || !argvEqual(c.Args, req.Argv) {
				continue
			}
			if specPass != nil && c.SpecSequence != specPass.Sequence {
				continue
			}
			redIdx = i
			break
		}
		if redIdx >= 0 {
			st = StatusFailureReproduced
			reasons = append(reasons, "red_failure_recorded")
		} else if specPass != nil {
			reasons = append(reasons, "red_failure_stale_or_missing")
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
		} else if review.HeadSHA != snap.HeadSHA || review.WorkspaceDigest != snap.WorkspaceDigest || review.BaseSHA != snap.BaseSHA {
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

func BuildReport(root string, t *Task, base string) (*Report, error) {
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
	reviews, revErr := LoadReviewSequence(root, t)
	if revErr != nil {
		// Malformed/duplicate/gapped review evidence fails closed as BLOCKED.
		return &Report{
			TaskID: t.TaskID, InvariantIDs: t.InvariantIDs,
			BaseSHA: snap.BaseSHA, HeadSHA: snap.HeadSHA, WorkspaceDigest: snap.WorkspaceDigest,
			WorktreeDirty: len(scope.Dirty) > 0, DerivedStatus: StatusBlocked,
			Reasons: []string{"invalid_review_evidence: " + revErr.Error()},
			Scope:   scope, Commands: cmds, EvidenceEditable: true, GeneratedUTC: time.Now().UTC(),
			Notes: []string{"review journal is malformed/duplicated/gapped; status blocked"},
		}, nil
	}
	review := latestJournalReview(reviews)
	st, reasons := DeriveStatus(t, cmds, scope, review, reviews, snap)
	digest, digestErr := ContractDigest(t)
	specPass := false
	if specRegime(t) && digestErr == nil {
		specPass = currentSpecPass(reviews, digest, t.SpecRevision) != nil
	}
	stopLoss := ""
	for _, r := range reasons {
		if strings.HasPrefix(r, "same_failure_class_stop_loss:") {
			stopLoss = r
			break
		}
	}
	return &Report{
		TaskID: t.TaskID, InvariantIDs: t.InvariantIDs,
		BaseSHA: snap.BaseSHA, HeadSHA: snap.HeadSHA, WorkspaceDigest: snap.WorkspaceDigest,
		WorktreeDirty: len(scope.Dirty) > 0, DerivedStatus: st, Reasons: reasons, Scope: scope,
		Commands: cmds, Review: review, SpecPass: specPass, ContractDigest: digest, StopLoss: stopLoss,
		EvidenceEditable: true, GeneratedUTC: time.Now().UTC(),
		Notes: []string{
			"local evidence/workflow is editable and not tamper-proof",
			"CI-generated evidence is the planned stronger merge gate",
			"model prose cannot override command results",
			"Mayur merge/release approval is outside this tool",
			"command argv is bound by the task contract",
			"GREEN/harness/review evidence is bound to base SHA and workspace digest",
			"Repository artifacts must be under evidence/workflow/ or evidence/harness/",
			"max_attempts is counted per pass-target name",
			"security tasks require a current passing spec review (contract digest + spec_revision) before RED/commands",
			"review journal lives under evidence/workflow/<task>/reviews/ with contiguous <n>.json files",
			"RED freshness binds to the current spec review journal sequence, not clocks or file mtime",
		},
	}, nil
}

// LoadReviewSequence reads the ordered review journal under
// evidence/workflow/<task>/reviews/. Files must be named <positive-int>.json
// with a contiguous sequence 1..N; malformed JSON, duplicate numbers, or gaps
// fail closed (the caller maps the error to BLOCKED).
func LoadReviewSequence(root string, t *Task) ([]ReviewArtifact, error) {
	dir := filepath.Join(EvidenceDir(root, t.TaskID), "reviews")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type numbered struct {
		n    int
		path string
	}
	var files []numbered
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("invalid review evidence: unexpected directory %q", e.Name())
		}
		name := e.Name()
		stem, ok := strings.CutSuffix(name, ".json")
		if !ok || stem == "" {
			return nil, fmt.Errorf("invalid review evidence: file %q must be named <positive-int>.json", name)
		}
		n, err := strconv.Atoi(stem)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("invalid review evidence: file %q must be named <positive-int>.json", name)
		}
		files = append(files, numbered{n: n, path: filepath.Join(dir, name)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].n < files[j].n })
	for i, f := range files {
		if f.n != i+1 {
			return nil, fmt.Errorf("invalid review evidence: expected sequence %d but found %d (gap or duplicate)", i+1, f.n)
		}
	}
	var out []ReviewArtifact
	for _, f := range files {
		b, err := os.ReadFile(f.path)
		if err != nil {
			return nil, err
		}
		if err := rejectDuplicateJSONKeys(b); err != nil {
			return nil, fmt.Errorf("invalid review evidence %s: %w", filepath.Base(f.path), err)
		}
		var r ReviewArtifact
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("invalid review evidence %s: %w", filepath.Base(f.path), err)
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			if err == nil {
				return nil, fmt.Errorf("invalid review evidence %s: trailing JSON value", filepath.Base(f.path))
			}
			return nil, fmt.Errorf("invalid review evidence %s: %w", filepath.Base(f.path), err)
		}
		if r.Sequence != 0 && r.Sequence != f.n {
			return nil, fmt.Errorf("invalid review evidence %s: sequence field %d does not match filename %d", filepath.Base(f.path), r.Sequence, f.n)
		}
		r.Sequence = f.n
		// Do not derive chronology from recorded_utc or file mtime: both are
		// caller-controlled (copied JSON, cp -p, Chtimes). RED freshness uses
		// this filename sequence against CommandRecord.SpecSequence.
		if err := ValidateReviewArtifact(&r, t); err != nil {
			return nil, fmt.Errorf("invalid review evidence %s: %w", filepath.Base(f.path), err)
		}
		out = append(out, r)
	}
	return out, nil
}

// latestJournalReview returns the most recent implementation review in the
// ordered journal, or nil when there is none.
func latestJournalReview(reviews []ReviewArtifact) *ReviewArtifact {
	for i := len(reviews) - 1; i >= 0; i-- {
		if reviews[i].Phase != "spec" {
			return &reviews[i]
		}
	}
	return nil
}

// ValidateReviewArtifact checks structural validity against the task taxonomy.
// Phase "spec" requires a revision, contract digest, and (when passing and bound
// to the live contract) full attack-class coverage plus a non-empty
// counterexample. Historical spec entries keep their original digest/revision
// and are not revalidated against a later taxonomy. Implementation reviews bind
// to the contract digest + spec_revision as well as the snapshot; unknown
// failure classes fail closed only on the live contract.
func ValidateReviewArtifact(r *ReviewArtifact, t *Task) error {
	phase := r.Phase
	if phase == "" {
		phase = "implementation"
	}
	if phase != "spec" && phase != "implementation" {
		return fmt.Errorf("invalid review phase %q", r.Phase)
	}
	canon := canonicalClasses(t)
	liveDigest := ""
	if specRegime(t) {
		d, err := ContractDigest(t)
		if err != nil {
			return fmt.Errorf("contract digest: %w", err)
		}
		liveDigest = d
	}
	currentContract := specRegime(t) && r.ContractDigest == liveDigest && r.SpecRevision == t.SpecRevision
	if phase == "spec" {
		if r.SpecRevision < 1 {
			return errors.New("spec review requires spec_revision >= 1")
		}
		if strings.TrimSpace(r.ContractDigest) == "" {
			return errors.New("spec review requires contract_digest")
		}
		// Full current-taxonomy checks apply only to the live contract.
		// Revalidating historical passing specs against a later attack class
		// would BLOCK the append-only journal and prevent a valid new spec
		// review from ever being consulted.
		if currentContract {
			for _, c := range r.CoveredAttackClasses {
				if _, ok := canon[c]; !ok {
					return fmt.Errorf("spec review covers unknown attack class %q", c)
				}
			}
			for _, c := range r.ClosedFailureClasses {
				if _, ok := canon[c]; !ok {
					return fmt.Errorf("spec review closes unknown failure class %q", c)
				}
			}
			if r.Passed {
				for c := range canon {
					if !containsStr(r.CoveredAttackClasses, c) {
						return fmt.Errorf("passing spec review does not cover attack class %q", c)
					}
				}
				if len(clean(r.Counterexamples)) == 0 {
					return errors.New("passing spec review requires counterexamples")
				}
			}
		}
		return nil
	}
	// Unknown names on a live-contract implementation review fail closed so a
	// mistyped mapping cannot reset an unlatched streak. Historical reviews
	// (different digest/revision) keep old class names so a rename cannot
	// BLOCK the journal.
	if specRegime(t) {
		if strings.TrimSpace(r.ContractDigest) == "" || r.SpecRevision < 1 {
			return errors.New("implementation review requires contract_digest and spec_revision")
		}
		if currentContract {
			for _, fc := range r.FailureClasses {
				if _, ok := canon[fc]; !ok {
					return fmt.Errorf("unknown failure class %q", fc)
				}
			}
		}
	}
	// Every implementation review that can advance OR interrupt the
	// stop-loss streak (classed or classless, passed or failed) must be
	// bound to a snapshot; otherwise a stale, copied, or unrelated artifact
	// could increment or reset a failure-class streak for the wrong tip.
	if r.HeadSHA == "" || r.WorkspaceDigest == "" || r.BaseSHA == "" {
		return errors.New("implementation review requires head_sha, workspace_digest, base_sha")
	}
	// Findings without failure-class mappings would be silently treated as
	// "no classes" by stopLossClass, resetting every non-latched streak and
	// letting the same issue recur forever without reaching the threshold.
	// Non-security tasks have no taxonomy; ordinary review notes must not
	// be forced to invent failure classes.
	if specRegime(t) && len(r.Findings) > 0 && len(r.FailureClasses) == 0 {
		return errors.New("implementation review findings require at least one canonical failure_class")
	}
	return nil
}

// rejectDuplicateJSONKeys fails closed when an object repeats a member name.
// encoding/json otherwise keeps the last value even with DisallowUnknownFields,
// so a second "failure_classes":[] could silently reset an unlatched streak.
func rejectDuplicateJSONKeys(data []byte) error {
	return rejectDuplicateJSONKeysDec(json.NewDecoder(bytes.NewReader(data)))
}

func rejectDuplicateJSONKeysDec(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("expected JSON object key, got %v", keyTok)
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateJSONKeysDec(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := rejectDuplicateJSONKeysDec(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %s", delim)
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// LatestSpecReview returns the most recent spec review bound to the contract
// digest + spec_revision, regardless of verdict (latest current review wins).
func LatestSpecReview(reviews []ReviewArtifact, digest string, revision int) *ReviewArtifact {
	var latest *ReviewArtifact
	for i := range reviews {
		r := &reviews[i]
		if r.Phase == "spec" && r.ContractDigest == digest && r.SpecRevision == revision {
			latest = r
		}
	}
	return latest
}

// currentSpecPass returns the latest current spec review when it passed.
func currentSpecPass(reviews []ReviewArtifact, digest string, revision int) *ReviewArtifact {
	latest := LatestSpecReview(reviews, digest, revision)
	if latest == nil || !latest.Passed {
		return nil
	}
	return latest
}

// stopLossClass derives the contiguous per-class strike run from the ordered
// review journal. Implementation reviews advance classes they contain and end
// classes they do not (multiple findings of one class in a review count once);
// a current passing spec review — bound to the live contract digest +
// spec_revision (aligned with currentSpecPass) — resets only the classes it
// lists in closed_failure_classes. At maxSameFailureClassStrikes the class and
// run length are returned; the class is the deterministic (sorted canonical
// order) first at/above threshold. No strike counters are stored.
func stopLossClass(t *Task, reviews []ReviewArtifact, digest string, revision int) (string, int, bool) {
	threshold := t.MaxSameFailureClassStrikes
	if threshold < 1 {
		return "", 0, false
	}
	canon := canonicalClasses(t)
	streaks := map[string]int{}
	// latched records classes that have already reached the threshold.
	// Once latched, an implementation review without the class does NOT
	// reset the streak (an interrupted pre-threshold run and an
	// already-triggered stop-loss are distinct); only a current passing
	// spec review listing the class in closed_failure_classes unlatches it.
	latched := map[string]bool{}
	for i := range reviews {
		r := &reviews[i]
		if r.Phase == "spec" {
			if r.Passed && r.ContractDigest == digest && r.SpecRevision == revision {
				closed := map[string]struct{}{}
				for _, c := range r.ClosedFailureClasses {
					closed[c] = struct{}{}
				}
				for c := range streaks {
					if _, ok := closed[c]; ok {
						streaks[c] = 0
						latched[c] = false
					}
				}
			}
			continue
		}
		has := map[string]struct{}{}
		for _, c := range r.FailureClasses {
			has[c] = struct{}{}
		}
		for c := range canon {
			if latched[c] {
				// Already triggered; cannot be unlatched by an
				// implementation review, only by spec closure.
				continue
			}
			if _, ok := has[c]; ok {
				streaks[c]++
				if streaks[c] >= threshold {
					latched[c] = true
				}
			} else {
				streaks[c] = 0
			}
		}
	}
	var candidates []string
	for c, n := range streaks {
		if latched[c] || n >= threshold {
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		return "", 0, false
	}
	sort.Strings(candidates)
	first := candidates[0]
	if latched[first] {
		return first, threshold, true
	}
	return first, streaks[first], true
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
	underExcluded := rel == "evidence/workflow" || strings.HasPrefix(rel, "evidence/workflow/") ||
		rel == "evidence/harness" || strings.HasPrefix(rel, "evidence/harness/")
	if inside && !underExcluded {
		return fmt.Errorf("%s artifact inside repository must be stored under evidence/workflow/, evidence/harness/, or outside the repository", kind)
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
	case StatusSpecified, StatusSpecReviewed, StatusFailureReproduced, StatusTargetVerified, StatusHarnessVerified, StatusSecurityReviewed:
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
	case StatusUnspecified, StatusSpecified, StatusSpecReviewed, StatusFailureReproduced, StatusTargetVerified,
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
	case StatusSpecReviewed:
		return 2
	case StatusFailureReproduced:
		return 3
	case StatusTargetVerified:
		return 4
	case StatusHarnessVerified:
		return 5
	case StatusSecurityReviewed:
		return 6
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
