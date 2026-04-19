package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "oy",
	Short: "Scan Markdown files for harmful or malicious instructions",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func printWarnings(warnings []string) {
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w)
	}
}
