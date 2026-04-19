package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aljoshare/oy/internal/repos"
)

var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "Manage policy repositories",
}

var repoAddCmd = &cobra.Command{
	Use:   "add <url>",
	Short: "Add a policy repository",
	Long: `Add a policy repository by URL. The repository is cloned locally and
its .rego files are used when scanning. Bare host/path references are
accepted in addition to full URLs. Append @ref to pin to a specific tag
or branch:

  oy repo add github.com/aljoshare/oy-policies
  oy repo add github.com/aljoshare/oy-policies@v1.2.0
  oy repo add https://github.com/myorg/my-policies@main`,
	Args: cobra.ExactArgs(1),
	RunE: runRepoAdd,
}

var repoListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered policy repositories",
	RunE:  runRepoList,
}

func init() {
	repoCmd.AddCommand(repoAddCmd)
	repoCmd.AddCommand(repoListCmd)
	rootCmd.AddCommand(repoCmd)
}

func runRepoAdd(cmd *cobra.Command, args []string) error {
	url := args[0]
	repo, err := repos.Add(url)
	if err != nil {
		return err
	}
	fmt.Printf("Added %s\n  cached at: %s\n", repo.URL, repo.LocalPath)
	return nil
}

func runRepoList(cmd *cobra.Command, args []string) error {
	cfg, err := repos.Load()
	if err != nil {
		return err
	}
	if len(cfg.Repos) == 0 {
		fmt.Println("No policy repositories registered.")
		fmt.Println("Add one with: oy repo add github.com/aljoshare/oy-policies")
		return nil
	}
	for _, r := range cfg.Repos {
		fmt.Printf("%s\n  %s\n", r.URL, r.LocalPath)
	}
	return nil
}
