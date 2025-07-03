package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/types"
)

var reachOptions struct {
	from     string
	fromCIDR string
	to       string
	toCIDR   string
}

func init() {
	reachCmd.Flags().StringVar(&reachOptions.from, "from", "", "egress pod")
	reachCmd.Flags().StringVar(&reachOptions.fromCIDR, "from-cidr", "", "egress CIDR")
	reachCmd.Flags().StringVar(&reachOptions.to, "to", "", "ingress pod")
	reachCmd.Flags().StringVar(&reachOptions.toCIDR, "to-cidr", "", "ingress CIDR")
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
		return runReach(context.Background(), cmd.OutOrStdout())
	},
}

type reachEntry struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Direction        string `json:"direction"`
	Policy           string `json:"policy"`
	Identity         int    `json:"identity"`
	WildcardProtocol bool   `json:"wildcard_protocol"`
	WildcardPort     bool   `json:"wildcard_port"`
	Protocol         int    `json:"protocol"`
	Port             int    `json:"port"`
	Bytes            int    `json:"bytes"`
	Packets          int    `json:"packets"`
}

func runReach(ctx context.Context, w io.Writer) error {
	var from, to *types.NamespacedName
	var fromCIDR, toCIDR *net.IPNet
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
	if reachOptions.fromCIDR != "" {
		cidr, err := parseCIDR(reachOptions.fromCIDR)
		if err != nil {
			return fmt.Errorf("failed to parse --from-cidr: %w", err)
		}
		fromCIDR = cidr
	}
	if reachOptions.toCIDR != "" {
		cidr, err := parseCIDR(reachOptions.toCIDR)
		if err != nil {
			return fmt.Errorf("failed to parse --to-cidr: %w", err)
		}
		toCIDR = cidr
	}

	if from == nil && to == nil {
		// For example, npv reach --from-cidr [CIDR] --to-cidr [CIDR] is non-sense
		// because both sides are not Cilium-managed and thus it can print nothing.
		// To obtain a meaningful result, one of --from or --to must be specified.
		return errors.New("one of --from or --to must be specified")
	}
	if from != nil && fromCIDR != nil {
		return errors.New("one of --from or --from-cidr can be specified")
	}
	if to != nil && toCIDR != nil {
		return errors.New("one of --to or --to-cidr can be specified")
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
			filter = makeIdentityFilter(false, true, int(identity))
		case toCIDR != nil:
			filter = makeCIDRFilter(false, true, toCIDR)
		default:
			return errors.New("one of --to or --to-cidr must be specified")
		}

		client, err := createCiliumClient(ctx, clientset, from.Namespace, from.Name)
		if err != nil {
			return err
		}

		policies, err := queryPolicyMap(ctx, clientset, dynamicClient, from.Namespace, from.Name)
		if err != nil {
			return err
		}
		if policies, err = filterPolicyMap(ctx, client, policies, filter); err != nil {
			return err
		}

		for _, p := range policies {
			var entry reachEntry
			entry.Namespace = from.Namespace
			entry.Name = from.Name
			entry.Direction = directionEgress
			if p.IsDenyRule() {
				entry.Policy = policyDeny
			} else {
				entry.Policy = policyAllow
			}
			entry.Identity = p.Key.Identity
			entry.WildcardProtocol = p.IsWildcardProtocol()
			entry.WildcardPort = p.IsWildcardPort()
			entry.Protocol = p.Key.Protocol
			entry.Port = p.Key.Port()
			entry.Bytes = p.Bytes
			entry.Packets = p.Packets
			arr = append(arr, entry)
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
			filter = makeIdentityFilter(true, false, int(identity))
		case fromCIDR != nil:
			filter = makeCIDRFilter(true, false, fromCIDR)
		default:
			return errors.New("one of --from or --from-cidr must be specified")
		}

		client, err := createCiliumClient(ctx, clientset, to.Namespace, to.Name)
		if err != nil {
			return err
		}

		policies, err := queryPolicyMap(ctx, clientset, dynamicClient, to.Namespace, to.Name)
		if policies, err = filterPolicyMap(ctx, client, policies, filter); err != nil {
			return err
		}

		for _, p := range policies {
			var entry reachEntry
			entry.Namespace = to.Namespace
			entry.Name = to.Name
			entry.Direction = directionIngress
			if p.IsDenyRule() {
				entry.Policy = policyDeny
			} else {
				entry.Policy = policyAllow
			}
			entry.Identity = p.Key.Identity
			entry.WildcardProtocol = p.IsWildcardProtocol()
			entry.WildcardPort = p.IsWildcardPort()
			entry.Protocol = p.Key.Protocol
			entry.Port = p.Key.Port()
			entry.Bytes = p.Bytes
			entry.Packets = p.Packets
			arr = append(arr, entry)
		}
	}

	header := []string{"NAMESPACE", "NAME", "DIRECTION", "POLICY", "IDENTITY", "PROTOCOL", "PORT", "BYTES", "PACKETS"}
	return writeSimpleOrJson(w, arr, header, len(arr), func(index int) []any {
		p := arr[index]
		var protocol, port string
		if p.WildcardProtocol {
			protocol = "ANY"
		} else {
			protocol = u8proto.U8proto(p.Protocol).String()
		}
		if p.WildcardPort {
			port = "ANY"
		} else {
			port = strconv.Itoa(p.Port)
		}
		return []any{p.Namespace, p.Name, p.Direction, p.Policy, p.Identity, protocol, port, p.Bytes, p.Packets}
	})
}
