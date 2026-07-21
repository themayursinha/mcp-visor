// Command visor-workflow — supervised checks; status derived from artifacts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/themayursinha/mcp-visor/internal/workflow"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	root, _ := os.Getwd()
	if r := os.Getenv("VISOR_WORKFLOW_ROOT"); r != "" {
		root = r
	}
	switch os.Args[1] {
	case "validate":
		os.Exit(cmdValidate(os.Args[2:]))
	case "scope":
		os.Exit(cmdScope(root, os.Args[2:]))
	case "run":
		os.Exit(cmdRun(root, os.Args[2:]))
	case "verify":
		os.Exit(cmdVerify(root, os.Args[2:]))
	case "report":
		os.Exit(cmdReport(root, os.Args[2:]))
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `visor-workflow validate|scope|run|verify|report
  validate -task f.json
  scope    -task f.json [-base ref]
  run      -task f.json -name N
  verify   -task f.json [-base ref] [-review r.json] [-min STATUS]
  report   -task f.json [-base ref] [-review r.json] [-out out.json]
run executes task-defined argv only (no -- override). Status is derived.`)
}

func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	taskPath := fs.String("task", "", "")
	if fs.Parse(args) != nil || *taskPath == "" {
		return 2
	}
	t, err := workflow.LoadTask(*taskPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		return 1
	}
	fmt.Printf("OK task_id=%s invariants=%s\n", t.TaskID, strings.Join(t.InvariantIDs, ","))
	return 0
}

func cmdScope(root string, args []string) int {
	fs := flag.NewFlagSet("scope", flag.ContinueOnError)
	taskPath := fs.String("task", "", "")
	base := fs.String("base", "", "")
	if fs.Parse(args) != nil || *taskPath == "" {
		return 2
	}
	t, err := workflow.LoadTask(*taskPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		return 1
	}
	res, err := workflow.CheckScope(root, t, *base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	if !res.Pass {
		return 1
	}
	return 0
}

func cmdRun(root string, args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	taskPath := fs.String("task", "", "")
	name := fs.String("name", "", "")
	base := fs.String("base", "", "")
	if fs.Parse(args) != nil || *taskPath == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "usage: run -task f.json -name NAME")
		return 2
	}
	// Reject leftover args / attempted command substitution.
	if rest := fs.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected args %v (command argv comes from the task contract)\n", rest)
		return 2
	}
	t, err := workflow.LoadTask(*taskPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		return 1
	}
	rec, err := workflow.RunNamedCommand(root, t, *name, *base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	fmt.Printf("recorded name=%s exit=%d source=executed digest=%s\n", rec.Name, rec.Exit, rec.WorkspaceDigest[:12])
	return rec.Exit
}

func cmdVerify(root string, args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	taskPath := fs.String("task", "", "")
	base := fs.String("base", "", "")
	reviewPath := fs.String("review", "", "")
	minStatus := fs.String("min", "TARGET_VERIFIED", "")
	if fs.Parse(args) != nil || *taskPath == "" {
		return 2
	}
	need, err := workflow.ParseStatus(*minStatus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	t, err := workflow.LoadTask(*taskPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		return 1
	}
	rev, err := workflow.LoadReview(*reviewPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "review: %v\n", err)
		return 2
	}
	rep, err := workflow.BuildReport(root, t, *base, rev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"derived_status":    rep.DerivedStatus,
		"reasons":           rep.Reasons,
		"scope_pass":        rep.Scope.Pass,
		"approval_gated":    rep.Scope.ApprovalGated,
		"worktree_dirty":    rep.WorktreeDirty,
		"base_sha":          rep.BaseSHA,
		"head_sha":          rep.HeadSHA,
		"workspace_digest":  rep.WorkspaceDigest,
		"evidence_editable": rep.EvidenceEditable,
	})
	if workflow.StatusRank(rep.DerivedStatus) >= workflow.StatusRank(need) {
		return 0
	}
	return 1
}

func cmdReport(root string, args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	taskPath := fs.String("task", "", "")
	base := fs.String("base", "", "")
	reviewPath := fs.String("review", "", "")
	out := fs.String("out", "", "")
	if fs.Parse(args) != nil || *taskPath == "" {
		return 2
	}
	t, err := workflow.LoadTask(*taskPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		return 1
	}
	rev, err := workflow.LoadReview(*reviewPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "review: %v\n", err)
		return 2
	}
	rep, err := workflow.BuildReport(root, t, *base, rev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(workflow.EvidenceDir(root, t.TaskID), "report.json")
	}
	if err := workflow.WriteReportJSON(outPath, rep); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 2
	}
	fmt.Println(outPath)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
	return 0
}
