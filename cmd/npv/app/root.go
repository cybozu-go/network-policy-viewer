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

type cidrOptions struct {
	cidrs        string
	privateCIDRs bool
	publicCIDRs  bool
}

func (c cidrOptions) isSet() bool {
	return c.cidrs != "" || c.privateCIDRs || c.publicCIDRs
}

var commonOptions struct {
	with cidrOptions
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
	cmd.Flags().StringVar(&commonOptions.with.cidrs, "with-cidrs", "", "show rules for CIDRs")
	cmd.Flags().BoolVar(&commonOptions.with.privateCIDRs, "with-private-cidrs", false, "show rules for private CIDRs")
	cmd.Flags().BoolVar(&commonOptions.with.publicCIDRs, "with-public-cidrs", false, "show rules for public CIDRs")
}

func parseCIDROptions(prefix string, opts *cidrOptions) (policyFilter, error) {
	count := 0
	expr := ""
	if opts.cidrs != "" {
		count += 1
		expr = opts.cidrs
	}
	if opts.privateCIDRs {
		count += 1
		expr = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	}
	if opts.publicCIDRs {
		count += 1
		expr = "0.0.0.0/0,!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16"
	}
	switch count {
	case 0:
		return nil, nil
	case 1:
		incl, excl, err := parseCIDRFlag(expr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse --%s-cidrs: %w", prefix, err)
		}
		return makeCIDRFilter(true, true, incl, excl), nil
	default:
		return nil, fmt.Errorf("one of --%s-cidrs, --%s-private-cidrs, --%s-public-cidrs can be specified", prefix, prefix, prefix)
	}
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
