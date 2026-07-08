package app

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootOptions struct {
	tlsCertFile       string
	tlsPrivateKeyFile string
}

var rootCmd = &cobra.Command{
	Use:   "cilium-agent-proxy",
	Short: "cilium-agent proxy",
	Long:  `cilium-agent proxy`,

	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return subMain()
	},
}

func init() {
	rootCmd.Flags().StringVar(&rootOptions.tlsCertFile, "tls-cert-file", "", "TLS certificate file for serving HTTPS")
	rootCmd.Flags().StringVar(&rootOptions.tlsPrivateKeyFile, "tls-private-key-file", "", "TLS private key file for serving HTTPS")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
