package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/themayursinha/mcp-visor/internal/policy"
)

func main() {
	lintCmd := flag.NewFlagSet("lint", flag.ExitOnError)
	jsonFlag := lintCmd.Bool("json", false, "Output in JSON format")
	strictFlag := lintCmd.Bool("strict", false, "Treat warnings as errors (exit non-zero on any finding)")
	noInfoFlag := lintCmd.Bool("no-info", false, "Hide info-level findings")
	noWarnFlag := lintCmd.Bool("no-warnings", false, "Hide warning-level findings")
	lintCmd.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: mcp-visor lint [flags] <policy-file>\n\nFlags:\n")
		lintCmd.PrintDefaults()
	}

	lintCmd.Parse(os.Args[2:])
	args := lintCmd.Args()

	if len(args) < 1 {
		lintCmd.Usage()
		os.Exit(1)
	}

	policyPath := args[0]

	pol, err := policy.LoadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-visor lint: failed to load policy: %v\n", err)
		os.Exit(1)
	}

	result := policy.Lint(pol)
	result.FilePath = policyPath

	if *noInfoFlag {
		filtered := make([]policy.LintViolation, 0, len(result.Violations))
		for _, v := range result.Violations {
			if v.Severity != policy.SeverityInfo {
				filtered = append(filtered, v)
			}
		}
		result.Violations = filtered
		result.Summary.Info = 0
		result.Summary.Total = len(filtered)
	}

	if *noWarnFlag {
		filtered := make([]policy.LintViolation, 0, len(result.Violations))
		for _, v := range result.Violations {
			if v.Severity != policy.SeverityWarning && v.Severity != policy.SeverityInfo {
				filtered = append(filtered, v)
			}
		}
		result.Violations = filtered
		result.Summary.Warnings = 0
		result.Summary.Info = 0
		result.Summary.Total = len(filtered)
	}

	if *jsonFlag {
		data, err := result.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-visor lint: JSON output error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		printText(&result)
	}

	if result.Summary.Errors > 0 {
		os.Exit(1)
	}

	if *strictFlag && (result.Summary.Warnings > 0 || result.Summary.Errors > 0) {
		os.Exit(1)
	}
}

func printText(result *policy.LintResult) {
	if result.Policy != "" {
		fmt.Printf("Policy: %s\n", result.Policy)
	}
	fmt.Printf("File: %s\n", result.FilePath)

	if result.Summary.Total == 0 {
		fmt.Println("No issues found.")
		return
	}

	sort.Slice(result.Violations, func(i, j int) bool {
		order := map[policy.Severity]int{
			policy.SeverityError:   0,
			policy.SeverityWarning: 1,
			policy.SeverityInfo:   2,
		}
		if order[result.Violations[i].Severity] != order[result.Violations[j].Severity] {
			return order[result.Violations[i].Severity] < order[result.Violations[j].Severity]
		}
		return result.Violations[i].Path < result.Violations[j].Path
	})

	fmt.Printf("Errors: %d  Warnings: %d  Info: %d\n\n", result.Summary.Errors, result.Summary.Warnings, result.Summary.Info)

	for _, v := range result.Violations {
		prefix := "[INFO]  "
		switch v.Severity {
		case policy.SeverityError:
			prefix = "[ERROR] "
		case policy.SeverityWarning:
			prefix = "[WARN]  "
		}
		fmt.Printf("%s%s\n", prefix, v.Message)
		fmt.Printf("        path=%s  field=%s\n", v.Path, v.Field)
	}
}
