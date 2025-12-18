package app

import "github.com/spf13/cobra"

func init() {
	rootCmd.AddCommand(agentCmd)
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Show cilium-agent name",
	Long:  `Show cilium-agent name`,
}
