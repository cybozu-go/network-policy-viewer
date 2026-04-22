package app

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cybozu-go/network-policy-viewer/pkg/cidr"
	"github.com/cybozu-go/network-policy-viewer/pkg/proxy"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

const (
	OutputJson   = "json"
	OutputSimple = "simple"
)

const (
	flagProxyNamespace = "proxy-namespace"
	flagProxySelector  = "proxy-selector"
	flagProxyPort      = "proxy-port"
	flagOutput         = "output"
	flagNoHeaders      = "no-headers"
	flagUnits          = "units"
	flagJobs           = "jobs"

	flagGroup             = "group"
	flagAllNamespaces     = "all-namespaces"
	flagNamespaceSelector = "namespace-selector"
	flagNamespace         = "namespace"
	flagPodSelector       = "selector"
	flagNode              = "node"
)

var rootOptions struct {
	output    string
	noHeaders bool
	units     bool
	jobs      int
}

func fillRootOptions() error {
	rootOptions.output = viper.GetString(flagOutput)
	rootOptions.noHeaders = viper.GetBool(flagNoHeaders)
	rootOptions.units = viper.GetBool(flagUnits)
	rootOptions.jobs = viper.GetInt(flagJobs)

	proxy.SetConfig(&proxy.Config{
		Namespace: viper.GetString(flagProxyNamespace),
		Selector:  viper.GetString(flagProxySelector),
		Port:      viper.GetUint16(flagProxyPort),
	})
	return nil
}

func fillGroupOptions(cmd *cobra.Command) error {
	if cmd.Flags().Lookup(flagGroup) != nil {
		group, err := cmd.Flags().GetString(flagGroup)
		if err != nil {
			return err
		}
		if err := subject.SetGroup(group); err != nil {
			return err
		}
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

func fillSelectorOptions(cmd *cobra.Command) error {
	config := &subject.SelectorConfig{}

	{
		num := 0
		if cmd.Flags().Changed(flagAllNamespaces) {
			num += 1
		}
		if cmd.Flags().Changed(flagNamespaceSelector) {
			num += 1
		}
		if cmd.Flags().Changed(flagNamespace) {
			num += 1
		}
		if cmd.Flags().Changed(flagNode) {
			num += 1
		}
		if num > 1 {
			return errors.New("at most one of --all-namespaces, --namespace-selector, --namespace, and --node may be specified")
		}
	}

	if cmd.Flags().Lookup(flagAllNamespaces) != nil {
		v, err := cmd.Flags().GetBool(flagAllNamespaces)
		if err != nil {
			return err
		}
		config.AllNamespaces = v
	}

	if cmd.Flags().Lookup(flagNamespaceSelector) != nil {
		v, err := cmd.Flags().GetString(flagNamespaceSelector)
		if err != nil {
			return err
		}
		config.NamespaceSelector = v
	}

	if cmd.Flags().Lookup(flagNamespace) != nil {
		v, err := cmd.Flags().GetString(flagNamespace)
		if err != nil {
			return err
		}
		config.Namespace = v
	}

	if cmd.Flags().Lookup(flagPodSelector) != nil {
		v, err := cmd.Flags().GetString(flagPodSelector)
		if err != nil {
			return err
		}
		config.PodSelector = v
	}

	if cmd.Flags().Lookup(flagNode) != nil {
		v, err := cmd.Flags().GetString(flagNode)
		if err != nil {
			return err
		}
		config.Node = v
	}

	if config.Node != "" {
		config.AllNamespaces = true
	}

	subject.SetSelectorConfig(config)
	return nil
}

var commonOptions struct {
	with cidrOptions
}

var policyOptions struct {
	ingress bool
	egress  bool
}

func fillPolicyOptions() {
	if !policyOptions.ingress && !policyOptions.egress {
		policyOptions.ingress = true
		policyOptions.egress = true
	}
}

func fillOptions(cmd *cobra.Command) error {
	if err := fillRootOptions(); err != nil {
		return err
	}
	if err := fillGroupOptions(cmd); err != nil {
		return err
	}
	if err := fillSelectorOptions(cmd); err != nil {
		return err
	}
	fillPolicyOptions()
	return nil
}

func init() {
	rootCmd.PersistentFlags().String(flagProxyNamespace, "cilium-agent-proxy", "namespace of the proxy pods")
	rootCmd.PersistentFlags().String(flagProxySelector, "app.kubernetes.io/name=cilium-agent-proxy", "label selector to find the proxy pods")
	rootCmd.PersistentFlags().Uint16(flagProxyPort, 8080, "port number of the proxy endpoints")
	rootCmd.PersistentFlags().StringP(flagOutput, "o", OutputSimple, "output format")
	rootCmd.PersistentFlags().Bool(flagNoHeaders, false, "stop printing header")
	rootCmd.PersistentFlags().BoolP(flagUnits, "u", false, "use human-readable units (power of 1024) for traffic volume")
	rootCmd.PersistentFlags().IntP(flagJobs, "j", 4, "number of parallel queries")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.SetEnvPrefix("npv")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func addGroupOption(cmd *cobra.Command) {
	cmd.Flags().StringP(flagGroup, "g", "pod", "merge entries within each subject group (pod [p], ns [n], all [a])")
}

// Use addNamespaceOption, addNamespaceSelectorOption, or addPodSelectorOption,
// depending on what the command needs.

// addNamespaceOption adds a flag for selecting a single namespace.
func addNamespaceOption(cmd *cobra.Command) {
	cmd.Flags().StringP(flagNamespace, "n", "", "namespace to select pods from")
	cmd.RegisterFlagCompletionFunc(flagNamespace, completeNamespaces)
}

// addNamespaceSelectorOption adds flags for selecting namespaces.
func addNamespaceSelectorOption(cmd *cobra.Command) {
	addNamespaceOption(cmd)
	cmd.Flags().BoolP(flagAllNamespaces, "A", false, "show pods across all namespaces")
	cmd.Flags().StringP(flagNamespaceSelector, "N", "", "namespace label selector")
}

// addPodSelectorOption adds flags for selecting pods across multiple namespaces.
func addPodSelectorOption(cmd *cobra.Command) {
	addNamespaceSelectorOption(cmd)
	cmd.Flags().StringP(flagPodSelector, "l", "", "pod label selector")
	cmd.Flags().String(flagNode, "", "node to filter pods by; implies -A (--all-namespaces)")
	cmd.RegisterFlagCompletionFunc(flagNode, completeNodes)
}

func addDirectionOption(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&policyOptions.ingress, "ingress", false, "show ingress-rules only")
	cmd.Flags().BoolVar(&policyOptions.egress, "egress", false, "show egress-rules only")
}

func addWithCIDROptions(cmd *cobra.Command) {
	cmd.Flags().StringVar(&commonOptions.with.cidrs, "with-cidrs", "", "show rules for CIDRs")
	cmd.Flags().BoolVar(&commonOptions.with.privateCIDRs, "with-private-cidrs", false, "show rules for private CIDRs (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)")
	cmd.Flags().BoolVar(&commonOptions.with.publicCIDRs, "with-public-cidrs", false, "show rules for public CIDRs (0.0.0.0/0,!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16)")
}

func parseCIDROptions(ingress, egress bool, prefix string, opts *cidrOptions) (proxy.PolicyFilter, error) {
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
		s, err := cidr.ParseCIDRExpression(expr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse --%s-cidrs: %w", prefix, err)
		}
		return proxy.MakeCIDRFilter(ingress, egress, *s), nil
	default:
		return nil, fmt.Errorf("one of --%s-cidrs, --%s-private-cidrs, --%s-public-cidrs can be specified", prefix, prefix, prefix)
	}
}

var rootCmd = &cobra.Command{
	Use: "npv",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return fillOptions(cmd)
	},
}

func Execute() {
	cobra.EnableTraverseRunHooks = true
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
