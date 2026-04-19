package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/aljoshare/oy/internal/policy"
	"github.com/aljoshare/oy/internal/repos"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all loaded rules with their titles",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVarP(&flagPoliciesDir, "policies", "p", "", "directory of .rego policy files to use instead of registered repos")
	listCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "output format: text or json")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

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

	printWarnings(evaluator.Warnings)

	rules, err := evaluator.Rules()
	if err != nil {
		return fmt.Errorf("reading rule metadata: %w", err)
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Title < rules[j].Title })

	switch flagFormat {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rules)
	default:
		for _, r := range rules {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", r.Title)
			if r.Description != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", r.Description)
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\n%d rule(s) loaded\n", len(rules))
	}
	return nil
}
