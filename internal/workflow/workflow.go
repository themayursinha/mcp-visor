// Package workflow derives supervised workflow status from artifacts only.
package workflow

import (
	"bytes"
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

type ReqCmd struct {
	Name   string `json:"name"`
	Expect string `json:"expect"` // pass|fail
}

type CommandRecord struct {
	Name        string    `json:"name"`
	Args        []string  `json:"args"`
	Exit        int       `json:"exit"`
	Source      string    `json:"source"`
	LogPath     string    `json:"log_path,omitempty"`
	RecordedUTC time.Time `json:"recorded_utc"`
}

type ReviewArtifact struct {
	Passed   bool     `json:"passed"`
	Findings []string `json:"findings"`
	Reviewer string   `json:"reviewer,omitempty"`
	Notes    string   `json:"notes,omitempty"`
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
	if err := ValidateTask(&t); err != nil {
		return nil, err
	}
	if len(t.ApprovalGatedPaths) == 0 {
		t.ApprovalGatedPaths = DefaultApprovalGated()
	}
	return &t, nil
}

func ValidateTask(t *Task) error {
	var e []string
	if strings.TrimSpace(t.TaskID) == "" {
		e = append(e, "task_id required")
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
	for i := range t.RequiredCommands {
		c := &t.RequiredCommands[i]
		c.Expect = strings.ToLower(strings.TrimSpace(c.Expect))
		if strings.TrimSpace(c.Name) == "" {
			e = append(e, fmt.Sprintf("required_commands[%d].name required", i))
		}
		if c.Expect != "pass" && c.Expect != "fail" {
			e = append(e, fmt.Sprintf("required_commands[%d].expect must be pass|fail", i))
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
	if len(e) > 0 {
		return errors.New(strings.Join(e, "; "))
	}
	return nil
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

func RunCommand(root, taskID, name string, args []string) (CommandRecord, error) {
	if len(args) == 0 {
		return CommandRecord{}, errors.New("command args required")
	}
	dir := EvidenceDir(root, taskID)
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return CommandRecord{}, err
	}
	logPath := filepath.Join(logDir, time.Now().UTC().Format("20060102T150405Z")+"-"+sanitize(name)+".log")
	f, err := os.Create(logPath)
	if err != nil {
		return CommandRecord{}, err
	}
	defer f.Close()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = root
	cmd.Stdout = io.MultiWriter(f, os.Stdout)
	cmd.Stderr = io.MultiWriter(f, os.Stderr)
	err = cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			return CommandRecord{}, err
		}
	}
	rec := CommandRecord{Name: name, Args: append([]string(nil), args...), Exit: exit, Source: "executed", LogPath: logPath, RecordedUTC: time.Now().UTC()}
	line, _ := json.Marshal(rec)
	out, err := os.OpenFile(commandsPath(root, taskID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
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
	return strings.TrimSpace(stdout.String()), nil
}

func ResolveBase(root, base string) (string, error) {
	if strings.TrimSpace(base) != "" {
		return git(root, "rev-parse", base)
	}
	if out, err := git(root, "merge-base", "HEAD", "origin/main"); err == nil && out != "" {
		return out, nil
	}
	return git(root, "rev-parse", "HEAD")
}

func CheckScope(root string, t *Task, base string) (ScopeResult, error) {
	baseSHA, err := ResolveBase(root, base)
	if err != nil {
		return ScopeResult{}, err
	}
	changed := map[string]struct{}{}
	addNS := func(s string) {
		for _, line := range strings.Split(s, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 2 {
				continue
			}
			st := fields[0]
			if strings.HasPrefix(st, "R") || strings.HasPrefix(st, "C") {
				if len(fields) >= 3 {
					changed[fields[1]], changed[fields[2]] = struct{}{}, struct{}{}
				}
				continue
			}
			changed[fields[len(fields)-1]] = struct{}{}
		}
	}
	if s, err := git(root, "diff", "--name-status", baseSHA); err == nil {
		addNS(s)
	} else {
		return ScopeResult{}, err
	}
	if s, _ := git(root, "diff", "--name-status", "--cached"); s != "" {
		addNS(s)
	}
	if s, _ := git(root, "ls-files", "--others", "--exclude-standard"); s != "" {
		for _, line := range strings.Split(s, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				changed[line] = struct{}{}
			}
		}
	}
	var dirty []string
	if s, _ := git(root, "status", "--porcelain"); s != "" {
		for _, line := range strings.Split(s, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			p := strings.TrimSpace(line[3:])
			if i := strings.Index(p, " -> "); i >= 0 {
				p = p[i+4:]
			}
			if p != "" {
				dirty = append(dirty, p)
			}
		}
	}
	var list, oos, gated []string
	for p := range changed {
		if strings.HasPrefix(p, "evidence/") {
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
			if target, err := filepath.EvalSymlinks(full); err == nil {
				if rel, err := filepath.Rel(root, target); err != nil || strings.HasPrefix(rel, "..") {
					oos = append(oos, p+"->SYMLINK_ESCAPE")
				}
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

func lastExec(cmds []CommandRecord, name string) *CommandRecord {
	for i := len(cmds) - 1; i >= 0; i-- {
		if cmds[i].Name == name && cmds[i].Source == "executed" {
			c := cmds[i]
			return &c
		}
	}
	return nil
}

func DeriveStatus(t *Task, cmds []CommandRecord, scope ScopeResult, review *ReviewArtifact) (Status, []string) {
	if err := ValidateTask(t); err != nil {
		return StatusUnspecified, []string{"invalid_task: " + err.Error()}
	}
	var reasons []string
	for _, c := range cmds {
		if c.Source != "executed" {
			return StatusBlocked, []string{"invalid_command_record:" + c.Name}
		}
	}
	st := StatusSpecified
	reasons = append(reasons, "valid_task_contract")

	redOK := !t.SecuritySensitive
	if t.SecuritySensitive {
		var red *CommandRecord
		for _, r := range t.RequiredCommands {
			if r.Expect == "fail" {
				if c := lastExec(cmds, r.Name); c != nil && c.Exit != 0 {
					red = c
					break
				}
			}
		}
		if red == nil {
			if c := lastExec(cmds, "red_test"); c != nil && c.Exit != 0 {
				red = c
			}
		}
		if red != nil {
			st, redOK = StatusFailureReproduced, true
			reasons = append(reasons, "red_failure_recorded")
		} else {
			reasons = append(reasons, "red_failure_missing")
		}
	}

	targetOK := scope.Pass && redOK
	if !scope.Pass {
		reasons = append(reasons, "scope_not_pass")
	}
	for _, r := range t.RequiredCommands {
		if r.Name == "harness" || r.Expect == "fail" {
			continue
		}
		c := lastExec(cmds, r.Name)
		if c == nil || c.Exit != 0 {
			targetOK = false
			reasons = append(reasons, "required_pass_missing_or_failed:"+r.Name)
		}
	}
	if targetOK {
		st = StatusTargetVerified
		reasons = append(reasons, "scope_and_targets_pass")
	}

	if st == StatusTargetVerified {
		h := lastExec(cmds, "harness")
		switch {
		case h != nil && h.Exit == 0:
			st = StatusHarnessVerified
			reasons = append(reasons, "harness_pass")
		case h != nil:
			reasons = append(reasons, "harness_failed")
		default:
			reasons = append(reasons, "harness_missing")
		}
	}

	if review != nil && review.Passed {
		if st == StatusHarnessVerified {
			st = StatusSecurityReviewed
			reasons = append(reasons, "review_pass")
		} else {
			reasons = append(reasons, "review_ignored_gates_not_met")
		}
	}
	return st, reasons
}

func BuildReport(root string, t *Task, base string, review *ReviewArtifact) (*Report, error) {
	baseSHA, err := ResolveBase(root, base)
	if err != nil {
		return nil, err
	}
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	scope, err := CheckScope(root, t, baseSHA)
	if err != nil {
		return nil, err
	}
	cmds, err := LoadCommands(root, t.TaskID)
	if err != nil {
		return nil, err
	}
	st, reasons := DeriveStatus(t, cmds, scope, review)
	return &Report{
		TaskID: t.TaskID, InvariantIDs: t.InvariantIDs, BaseSHA: baseSHA, HeadSHA: head,
		WorktreeDirty: len(scope.Dirty) > 0, DerivedStatus: st, Reasons: reasons, Scope: scope,
		Commands: cmds, Review: review, EvidenceEditable: true, GeneratedUTC: time.Now().UTC(),
		Notes: []string{
			"local evidence/workflow is editable and not tamper-proof",
			"CI-generated evidence is the planned stronger merge gate",
			"model prose cannot override command results",
			"Mayur merge/release approval is outside this tool",
			"roles are operational (profiles/credentials/GitHub), not env identity",
		},
	}, nil
}

func LoadReview(path string) (*ReviewArtifact, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r ReviewArtifact
	return &r, json.Unmarshal(b, &r)
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
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
