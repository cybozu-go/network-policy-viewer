package app

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	OutputJson   = "json"
	OutputSimple = "simple"
)

const (
	flagNamespace      = "namespace"
	flagProxyNamespace = "proxy-namespace"
	flagProxySelector  = "proxy-selector"
	flagProxyPort      = "proxy-port"
	flagOutput         = "output"
	flagNoHeaders      = "no-headers"
	flagUnits          = "units"
	flagJobs           = "jobs"
)

var rootOptions struct {
	namespace      string
	proxyNamespace string
	proxySelector  string
	proxyPort      uint16
	output         string
	noHeaders      bool
	units          bool
	jobs           int
}

func fillRootOptions(cmd *cobra.Command) error {
	rootOptions.namespace = viper.GetString(flagNamespace)
	rootOptions.proxyNamespace = viper.GetString(flagProxyNamespace)
	rootOptions.proxySelector = viper.GetString(flagProxySelector)
	rootOptions.proxyPort = viper.GetUint16(flagProxyPort)
	rootOptions.output = viper.GetString(flagOutput)
	rootOptions.noHeaders = viper.GetBool(flagNoHeaders)
	rootOptions.units = viper.GetBool(flagUnits)
	rootOptions.jobs = viper.GetInt(flagJobs)

	if selectorOptions.node != "" {
		selectorOptions.allNamespaces = true
	}

	switch {
	case cmd.Flags().Changed(flagNamespace) && selectorOptions.allNamespaces:
		return errors.New("namespace (-n) and all-namespaces (-A) should not be specified at once")
	case cmd.Flags().Changed(flagNamespace) && selectorOptions.namespaceSelector != "":
		return errors.New("namespace (-n) and namespace-selector (-N) should not be specified at once")
	}
	return nil
}

type cidrOptions struct {
	cidrs        string
	privateCIDRs bool
	publicCIDRs  bool
}

func (c cidrOptions) isSet() bool {
	return c.cidrs != "" || c.privateCIDRs || c.publicCIDRs
}

var selectorOptions struct {
	allNamespaces     bool
	namespaceSelector string
	podSelector       string
	node              string
}

var commonOptions struct {
	with cidrOptions
}

func init() {
	rootCmd.PersistentFlags().StringP(flagNamespace, "n", "", "namespace of pods")
	rootCmd.PersistentFlags().String(flagProxyNamespace, "cilium-agent-proxy", "namespace of the proxy pods")
	rootCmd.PersistentFlags().String(flagProxySelector, "app.kubernetes.io/name=cilium-agent-proxy", "label selector to find the proxy pods")
	rootCmd.PersistentFlags().Uint16(flagProxyPort, 8080, "port number of the proxy endpoints")
	rootCmd.PersistentFlags().StringP(flagOutput, "o", OutputSimple, "output format")
	rootCmd.PersistentFlags().Bool(flagNoHeaders, false, "stop printing header")
	rootCmd.PersistentFlags().BoolP(flagUnits, "u", false, "use human-readable units (power of 1024) for traffic volume")
	rootCmd.PersistentFlags().IntP(flagJobs, "j", 4, "number of parallel queries")
	rootCmd.RegisterFlagCompletionFunc(flagNamespace, completeNamespaces)

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.SetEnvPrefix("npv")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func addNamespaceSelectorOption(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&selectorOptions.allNamespaces, "all-namespaces", "A", false, "show pods across all namespaces")
	cmd.Flags().StringVarP(&selectorOptions.namespaceSelector, "namespace-selector", "N", "", "specify namespace label constraints")
}

func addSelectorOption(cmd *cobra.Command) {
	addNamespaceSelectorOption(cmd)
	cmd.Flags().StringVarP(&selectorOptions.podSelector, "selector", "l", "", "specify label constraints")
	cmd.Flags().StringVar(&selectorOptions.node, "node", "", "node of pods. It turns on -A (--all-namespaces).")
	cmd.RegisterFlagCompletionFunc("node", completeNodes)
}

func addWithCIDROptions(cmd *cobra.Command) {
	cmd.Flags().StringVar(&commonOptions.with.cidrs, "with-cidrs", "", "show rules for CIDRs")
	cmd.Flags().BoolVar(&commonOptions.with.privateCIDRs, "with-private-cidrs", false, "show rules for private CIDRs (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)")
	cmd.Flags().BoolVar(&commonOptions.with.publicCIDRs, "with-public-cidrs", false, "show rules for public CIDRs (0.0.0.0/0,!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16)")
}

func parseCIDROptions(ingress, egress bool, prefix string, opts *cidrOptions) (policyFilter, error) {
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
		return makeCIDRFilter(ingress, egress, incl, excl), nil
	default:
		return nil, fmt.Errorf("one of --%s-cidrs, --%s-private-cidrs, --%s-public-cidrs can be specified", prefix, prefix, prefix)
	}
}

var rootCmd = &cobra.Command{
	Use: "npv",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return fillRootOptions(cmd)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
