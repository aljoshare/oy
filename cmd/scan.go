package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aljoshare/oy/internal/policy"
	"github.com/aljoshare/oy/internal/repos"
	"github.com/aljoshare/oy/internal/scanner"
)

type scanResult struct {
	FilesScanned int                `json:"files_scanned"`
	Violations   []policy.Violation `json:"violations"`
}

var (
	flagPoliciesDir string
	flagFormat      string
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan Markdown files for harmful or malicious instructions",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&flagPoliciesDir, "policies", "p", "", "directory of .rego policy files to use instead of registered repos")
	scanCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "output format: text or json")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// Suppress usage output for runtime errors — usage is only helpful for
	// wrong invocations, not for "path not found" or "no repos configured".
	cmd.SilenceUsage = true

	root := args[0]

	var evaluator *policy.Evaluator
	var err error

	if flagPoliciesDir != "" {
		evaluator, err = policy.NewEvaluatorFromDir(flagPoliciesDir)
		if err != nil {
			return fmt.Errorf("loading policies: %w", err)
		}
	} else {
		cfg, err := repos.Load()
		if err != nil {
			return fmt.Errorf("loading repo config: %w", err)
		}
		if len(cfg.Repos) == 0 {
			return fmt.Errorf("no policy repositories configured\n\nAdd one with:\n  oy repo add github.com/aljoshare/oy-policies")
		}
		evaluator, err = policy.NewEvaluatorFromDirs(cfg.LocalPaths())
		if err != nil {
			return fmt.Errorf("loading policies: %w", err)
		}
	}

	files, err := scanner.FindMarkdownFiles(root)
	if err != nil {
		return fmt.Errorf("scanning %q: %w", root, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no Markdown files found in %q — check the path", root)
	}

	ctx := context.Background()
	var allViolations []policy.Violation

	for _, f := range files {
		violations, err := evaluator.Evaluate(ctx, f)
		if err != nil {
			return err
		}
		allViolations = append(allViolations, violations...)
	}

	result := scanResult{
		FilesScanned: len(files),
		Violations:   allViolations,
	}
	if result.Violations == nil {
		result.Violations = []policy.Violation{}
	}

	switch flagFormat {
	case "json":
		if err := printJSON(result); err != nil {
			return err
		}
	default:
		printText(result)
	}

	if len(allViolations) > 0 {
		os.Exit(1)
	}
	return nil
}

func printJSON(result scanResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func printText(result scanResult) {
	// Collect violations per file, preserving insertion order for stable output.
	seen := []string{}
	byFile := map[string][]string{}
	for _, v := range result.Violations {
		if _, ok := byFile[v.File]; !ok {
			seen = append(seen, v.File)
		}
		byFile[v.File] = append(byFile[v.File], v.Message)
	}

	for i, file := range seen {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("FAIL %s\n", file)
		for _, m := range byFile[file] {
			fmt.Printf("  - %s\n", m)
		}
	}

	violationCount := len(result.Violations)
	if violationCount == 0 {
		fmt.Printf("OK: %d file(s) scanned, no violations found\n", result.FilesScanned)
	} else {
		fmt.Printf("\nFAIL: %d file(s) scanned, %d violation(s) found\n", result.FilesScanned, violationCount)
	}
}
