package app

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	OutputJson   = "json"
	OutputSimple = "simple"
)

var rootOptions struct {
	namespace     string
	proxySelector string
	proxyPort     uint16
	output        string
	noHeaders     bool
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&rootOptions.namespace, "namespace", "n", "default", "namespace of a pod")
	rootCmd.PersistentFlags().StringVar(&rootOptions.proxySelector, "proxy-selector", "app.kubernetes.io/name=cilium-agent-proxy", "label selector to find the proxy pods")
	rootCmd.PersistentFlags().Uint16Var(&rootOptions.proxyPort, "proxy-port", 8080, "port number of the proxy endpoints")
	rootCmd.PersistentFlags().StringVarP(&rootOptions.output, "output", "o", OutputSimple, "output format")
	rootCmd.PersistentFlags().BoolVar(&rootOptions.noHeaders, "no-headers", false, "stop printing header")
	rootCmd.RegisterFlagCompletionFunc("namespace", completeNamespaces)
}

var rootCmd = &cobra.Command{
	Use: "npv",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
