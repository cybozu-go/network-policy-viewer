package app

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var reachOptions struct {
	from     string
	fromCIDR cidrOptions
	to       string
	toCIDR   cidrOptions
}

func init() {
	reachCmd.Flags().StringVar(&reachOptions.from, "from", "", "source pod")
	reachCmd.Flags().StringVar(&reachOptions.fromCIDR.cidrs, "from-cidrs", "", "source CIDRs")
	reachCmd.Flags().BoolVar(&reachOptions.fromCIDR.privateCIDRs, "from-private-cidrs", false, "use private CIDRs as source (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)")
	reachCmd.Flags().BoolVar(&reachOptions.fromCIDR.publicCIDRs, "from-public-cidrs", false, "use public CIDRs as source (0.0.0.0/0,!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16)")
	reachCmd.Flags().StringVar(&reachOptions.to, "to", "", "destination pod")
	reachCmd.Flags().StringVar(&reachOptions.toCIDR.cidrs, "to-cidrs", "", "destination CIDRs")
	reachCmd.Flags().BoolVar(&reachOptions.toCIDR.privateCIDRs, "to-private-cidrs", false, "use private CIDRs as destination (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)")
	reachCmd.Flags().BoolVar(&reachOptions.toCIDR.publicCIDRs, "to-public-cidrs", false, "use public CIDRs as destination (0.0.0.0/0,!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16)")
	reachCmd.Flags().BoolVar(&inspectOptions.maskCIDRs, "mask-cidrs", false, "mask cluster-external CIDRs and unify them into public, private, and unknown")
	reachCmd.RegisterFlagCompletionFunc("from", completeNamespacePods)
	reachCmd.RegisterFlagCompletionFunc("to", completeNamespacePods)
	rootCmd.AddCommand(reachCmd)
}

var reachCmd = &cobra.Command{
	Use:   "reach",
	Short: "List traffic policies between pod pair",
	Long:  `List traffic policies between pod pair`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runReach(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr())
	},
}

type reachEntry struct {
	inspectEntry
	Role string `json:"role"`
}

func runReach(ctx context.Context, stdout, stderr io.Writer) error {
	var from, to *types.NamespacedName
	if reachOptions.from != "" {
		f, err := parseNamespacedName(reachOptions.from)
		if err != nil {
			return errors.New("--from should be specified as NAMESPACE/POD")
		}
		from = &f
	}
	if reachOptions.to != "" {
		t, err := parseNamespacedName(reachOptions.to)
		if err != nil {
			return errors.New("--to should be specified as NAMESPACE/POD")
		}
		to = &t
	}

	if from == nil && to == nil {
		// For example, npv reach --from-cidrs [CIDR] --to-cidrs [CIDR] is non-sense
		// because both sides are not Cilium-managed and thus it can print nothing.
		// To obtain a meaningful result, one of --from or --to must be specified.
		return errors.New("one of --from or --to must be specified")
	}

	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	arr := make([]reachEntry, 0)

	// process from-egress
	if from != nil {
		var filter policyFilter

		switch {
		case to != nil:
			identity, err := getPodIdentity(ctx, dynamicClient, to.Namespace, to.Name)
			if err != nil {
				return err
			}
			filter = makeIdentityFilter(false, true, identity)
		case reachOptions.toCIDR.isSet():
			filter, err = parseCIDROptions(false, true, "to", &reachOptions.toCIDR)
			if err != nil {
				return err
			}
		default:
			return errors.New("one of --to or --to-cidrs must be specified")
		}

		pod, err := clientset.CoreV1().Pods(from.Namespace).Get(ctx, from.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		rules, err := runInspectOnPod(ctx, stderr, clientset, dynamicClient, filter, pod)
		if err != nil {
			return err
		}

		for _, r := range rules {
			arr = append(arr, reachEntry{
				inspectEntry: r,
				Role:         trafficRoleSender,
			})
		}
	}
	// process to-ingress
	if to != nil {
		var filter policyFilter

		switch {
		case from != nil:
			identity, err := getPodIdentity(ctx, dynamicClient, from.Namespace, from.Name)
			if err != nil {
				return err
			}
			filter = makeIdentityFilter(true, false, identity)
		case reachOptions.fromCIDR.isSet():
			filter, err = parseCIDROptions(true, false, "from", &reachOptions.fromCIDR)
			if err != nil {
				return err
			}
		default:
			return errors.New("one of --from or --from-cidrs must be specified")
		}

		pod, err := clientset.CoreV1().Pods(to.Namespace).Get(ctx, to.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		rules, err := runInspectOnPod(ctx, stderr, clientset, dynamicClient, filter, pod)
		if err != nil {
			return err
		}

		for _, r := range rules {
			arr = append(arr, reachEntry{
				inspectEntry: r,
				Role:         trafficRoleReceiver,
			})
		}
	}

	header := []string{"ROLE", "DIRECTION", "POLICY", "|", "IDENTITY", "NAMESPACE", "EXAMPLE-ENDPOINT", "|", "PROTOCOL", "PORT", "|", "BYTES:", "REQUESTS:", "AVERAGE:"}
	return writeSimpleOrJson(stdout, arr, header, len(arr), func(index int) []any {
		p := arr[index]
		protocol := u8proto.U8proto(p.Protocol).String()
		var port string
		if p.WildcardPort {
			port = "ANY"
		} else {
			port = fmt.Sprint(p.Port)
		}
		avg := fmt.Sprintf("%.1f", computeAverage(p.Bytes, p.Requests))
		return []any{p.Role, p.Direction, p.Policy, "|", p.Identity, p.Namespace, p.Example, "|", protocol, port, "|", formatWithUnits(p.Bytes), formatWithUnits(p.Requests), avg}
	})
}
