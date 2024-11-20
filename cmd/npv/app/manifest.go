package app

import "github.com/spf13/cobra"

func init() {
	rootCmd.AddCommand(manifestCmd)
}

var manifestCmd = &cobra.Command{
	Use:   "manifest",
	Short: "Generate CiliumNetworkPolicy",
	Long:  `Generate CiliumNetworkPolicy`,
}
