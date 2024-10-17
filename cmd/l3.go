package cmd

import "github.com/spf13/cobra"

var l3Cmd = &cobra.Command{
	Use:   "l3",
	Short: "inspect l3 rules",
	Long:  `inspect l3 rules`,
}

func init() {
	rootCmd.AddCommand(l3Cmd)
}
