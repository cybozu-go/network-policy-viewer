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
	units          bool
}

var commonOptions struct {
	withCIDR         string
	withPrivateCIDRs bool
	withPublicCIDRs  bool

	withCIDRFilter policyFilter
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
	rootCmd.PersistentFlags().BoolVarP(&rootOptions.units, "units", "u", false, "use human-readable units (power of 1024) for traffic volume")
	rootCmd.RegisterFlagCompletionFunc("namespace", completeNamespaces)
	rootCmd.RegisterFlagCompletionFunc("node", completeNodes)
}

func addWithCIDROptions(cmd *cobra.Command) {
	cmd.Flags().StringVar(&commonOptions.withCIDR, "with-cidr", "", "show rules for CIDR")
	cmd.Flags().BoolVar(&commonOptions.withPrivateCIDRs, "with-private-cidrs", false, "show rules for private CIDRs")
	cmd.Flags().BoolVar(&commonOptions.withPublicCIDRs, "with-public-cidrs", false, "show rules for public CIDRs")
}

func parseWithCIDROptions() error {
	count := 0
	expr := ""
	if commonOptions.withCIDR != "" {
		count += 1
		expr = commonOptions.withCIDR
	}
	if commonOptions.withPrivateCIDRs {
		count += 1
		expr = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	}
	if commonOptions.withPublicCIDRs {
		count += 1
		expr = "0.0.0.0/0,!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16"
	}
	switch count {
	case 0:
	case 1:
		incl, excl, err := parseCIDRFlag(expr)
		if err != nil {
			return fmt.Errorf("failed to parse --with-cidr: %w", err)
		}
		commonOptions.withCIDRFilter = makeCIDRFilter(true, true, incl, excl)
	default:
		return errors.New("one of --with-cidr, --with-private-cidrs, --with-public-cidrs can be specified")
	}
	return nil
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
