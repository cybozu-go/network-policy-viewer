package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
)

var reachOptions struct {
	from string
	to   string
}

func init() {
	reachCmd.Flags().StringVar(&reachOptions.from, "from", "", "egress pod")
	reachCmd.Flags().StringVar(&reachOptions.to, "to", "", "ingress pod")
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
	Requests         int    `json:"requests"`
}

func runReach(ctx context.Context, w io.Writer) error {
	if reachOptions.from == "" || reachOptions.to == "" {
		return errors.New("--from and --to options are required")
	}

	from, err := parseNamespacedName(reachOptions.from)
	if err != nil {
		return errors.New("--from and --to should be specified as NAMESPACE/POD")
	}

	to, err := parseNamespacedName(reachOptions.to)
	if err != nil {
		return errors.New("--from and --to should be specified as NAMESPACE/POD")
	}

	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	fromIdentity, err := getPodIdentity(ctx, dynamicClient, from.Namespace, from.Name)
	if err != nil {
		return err
	}

	toIdentity, err := getPodIdentity(ctx, dynamicClient, to.Namespace, to.Name)
	if err != nil {
		return err
	}

	fromPolicies, err := queryPolicyMap(ctx, clientset, dynamicClient, from.Namespace, from.Name)
	if err != nil {
		return err
	}

	toPolicies, err := queryPolicyMap(ctx, clientset, dynamicClient, to.Namespace, to.Name)
	if err != nil {
		return err
	}

	arr := make([]reachEntry, 0)
	for _, p := range fromPolicies {
		if (p.Key.Identity != 0) && (p.Key.Identity != int(toIdentity)) {
			continue
		}
		if !p.IsEgressRule() {
			continue
		}
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
		entry.Requests = p.Packets
		arr = append(arr, entry)
	}
	for _, p := range toPolicies {
		if (p.Key.Identity != 0) && (p.Key.Identity != int(fromIdentity)) {
			continue
		}
		if p.IsEgressRule() {
			continue
		}
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
		entry.Requests = p.Packets
		arr = append(arr, entry)
	}

	header := []string{"NAMESPACE", "NAME", "DIRECTION", "POLICY", "IDENTITY", "PROTOCOL", "PORT", "BYTES", "REQUESTS", "AVERAGE"}
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
		avg := fmt.Sprintf("%.1f", computeAverage(p.Bytes, p.Requests))
		return []any{p.Namespace, p.Name, p.Direction, p.Policy, p.Identity, protocol, port, formatWithUnits(p.Bytes), formatWithUnits(p.Requests), avg}
	})
}
