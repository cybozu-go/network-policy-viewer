package app

import "github.com/spf13/cobra"

func init() {
	rootCmd.AddCommand(idCmd)
}

var idCmd = &cobra.Command{
	Use:   "id",
	Short: "Inspect CiliumIdentity",
	Long:  `Inspect CiliumIdentity`,
}
