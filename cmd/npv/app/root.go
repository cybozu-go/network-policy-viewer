package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	OutputJson   = "json"
	OutputSimple = "simple"
)

var rootOptions struct {
	namespace      string
	allNamespaces  bool
	node           string
	proxyNamespace string
	proxySelector  string
	proxyPort      uint16
	output         string
	noHeaders      bool
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&rootOptions.namespace, "namespace", "n", "default", "namespace of pods")
	rootCmd.PersistentFlags().BoolVarP(&rootOptions.allNamespaces, "all-namespaces", "A", false, "show pods across all namespaces")
	rootCmd.PersistentFlags().StringVar(&rootOptions.node, "node", "", "node of pods. It turns on -A (--all-namespaces).")
	rootCmd.PersistentFlags().StringVar(&rootOptions.proxyNamespace, "proxy-namespace", "cilium-agent-proxy", "namespace of the proxy pods")
	rootCmd.PersistentFlags().StringVar(&rootOptions.proxySelector, "proxy-selector", "app.kubernetes.io/name=cilium-agent-proxy", "label selector to find the proxy pods")
	rootCmd.PersistentFlags().Uint16Var(&rootOptions.proxyPort, "proxy-port", 8080, "port number of the proxy endpoints")
	rootCmd.PersistentFlags().StringVarP(&rootOptions.output, "output", "o", OutputSimple, "output format")
	rootCmd.PersistentFlags().BoolVar(&rootOptions.noHeaders, "no-headers", false, "stop printing header")
	rootCmd.RegisterFlagCompletionFunc("namespace", completeNamespaces)
	rootCmd.RegisterFlagCompletionFunc("node", completeNodes)
}

var rootCmd = &cobra.Command{
	Use: "npv",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if rootOptions.node != "" {
			rootOptions.allNamespaces = true
		}
		if rootOptions.allNamespaces && cmd.Flags().Changed("namespace") {
			return errors.New("namespace (-n) and all-namespaces (-A) should not be specified at once")
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
