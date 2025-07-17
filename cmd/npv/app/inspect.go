package app

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"strconv"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var inspectOptions struct {
	ingress bool
	egress  bool
	allowed bool
	denied  bool
	used    bool
	unused  bool
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectOptions.ingress, "ingress", false, "show ingress-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.egress, "egress", false, "show egress-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.allowed, "allowed", false, "show allowed-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.denied, "denied", false, "show denied-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.used, "used", false, "show used-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.unused, "unused", false, "show unused-rules only")
	addWithCIDROptions(inspectCmd)
	rootCmd.AddCommand(inspectCmd)
}

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect network policies applied to a pod",
	Long:  `Inspect network policies applied to a pod`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInspect(context.Background(), cmd.OutOrStdout(), args[0])
	},
	ValidArgsFunction: completePods,
}

// This command aims to show the result of "cilium bpf policy get" from a remote pod.
// https://github.com/cilium/cilium/blob/v1.16.3/cilium-dbg/cmd/bpf_policy_get.go
type inspectEntry struct {
	Policy           string `json:"policy"`
	Direction        string `json:"direction"`
	Namespace        string `json:"namespace"`
	Example          string `json:"example_endpoint"`
	Identity         int    `json:"identity"`
	WildcardProtocol bool   `json:"wildcard_protocol"`
	WildcardPort     bool   `json:"wildcard_port"`
	Protocol         int    `json:"protocol"`
	Port             int    `json:"port"`
	Bytes            int    `json:"bytes"`
	Requests         int    `json:"requests"`
}

func parseInspectOptions() {
	if !inspectOptions.ingress && !inspectOptions.egress {
		inspectOptions.ingress = true
		inspectOptions.egress = true
	}
	if !inspectOptions.allowed && !inspectOptions.denied {
		inspectOptions.allowed = true
		inspectOptions.denied = true
	}
	if !inspectOptions.used && !inspectOptions.unused {
		inspectOptions.used = true
		inspectOptions.unused = true
	}
}

func runInspect(ctx context.Context, w io.Writer, name string) error {
	parseInspectOptions()
	basicFilter := makeBasicFilter(
		inspectOptions.ingress, inspectOptions.egress,
		inspectOptions.allowed, inspectOptions.denied,
		inspectOptions.used, inspectOptions.unused,
	)
	withFilter, err := parseCIDROptions(true, true, "with", &commonOptions.with)
	if err != nil {
		return err
	}
	filter := makeAllFilter(basicFilter, withFilter)

	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	client, err := createCiliumClient(ctx, clientset, rootOptions.namespace, name)
	if err != nil {
		return fmt.Errorf("failed to create Cilium client: %w", err)
	}

	policies, err := queryPolicyMap(ctx, clientset, dynamicClient, rootOptions.namespace, name)
	if err != nil {
		return err
	}
	if policies, err = filterPolicyMap(ctx, client, policies, filter); err != nil {
		return err
	}

	ids, err := getIdentityResourceMap(ctx, dynamicClient)
	if err != nil {
		return err
	}

	idEndpoints, err := getIdentityEndpoints(ctx, dynamicClient)
	if err != nil {
		return err
	}

	arr := make([]inspectEntry, len(policies))
	for i, p := range policies {
		var entry inspectEntry
		if p.IsDenyRule() {
			entry.Policy = policyDeny
		} else {
			entry.Policy = policyAllow
		}
		if p.IsEgressRule() {
			entry.Direction = directionEgress
		} else {
			entry.Direction = directionIngress
		}
		entry.Namespace = "-"
		if id, ok := ids[p.Key.Identity]; ok {
			ns, ok, err := unstructured.NestedString(id.Object, "security-labels", "k8s:io.kubernetes.pod.namespace")
			if err != nil {
				return err
			}
			if ok {
				entry.Namespace = ns
			}
		}
		entry.Example = "-"
		if v, ok := idEndpoints[p.Key.Identity]; ok {
			i := rand.IntN(len(v))
			entry.Example = v[i].GetName()
		} else {
			idObj := identity.NumericIdentity(p.Key.Identity)
			if idObj.IsReservedIdentity() {
				entry.Example = "reserved:" + idObj.String()
			} else if idObj.HasLocalScope() {
				response, err := queryLocalIdentity(ctx, client, p.Key.Identity)
				if err != nil {
					return err
				}
				if slices.Contains(response.Payload.Labels, "reserved:world") {
					lbls := labels.NewLabelsFromModel(response.Payload.Labels)
					cidrModel := lbls.GetFromSource(labels.LabelSourceCIDR).GetPrintableModel()
					if len(cidrModel) == 1 {
						entry.Example = cidrModel[0]
					}
				}
			}
		}
		entry.Identity = p.Key.Identity
		entry.WildcardProtocol = p.IsWildcardProtocol()
		entry.WildcardPort = p.IsWildcardPort()
		entry.Protocol = p.Key.Protocol
		entry.Port = p.Key.Port()
		entry.Bytes = p.Bytes
		entry.Requests = p.Packets
		arr[i] = entry
	}

	// I don't know it is safe to sort the result of "cilium bpf policy get", so let's keep the original order.
	header := []string{"POLICY", "DIRECTION", "|", "IDENTITY", "NAMESPACE", "EXAMPLE-ENDPOINT", "|", "PROTOCOL", "PORT", "|", "BYTES:", "REQUESTS:", "AVERAGE:"}
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
		return []any{p.Policy, p.Direction, "|", p.Identity, p.Namespace, p.Example, "|", protocol, port, "|", formatWithUnits(p.Bytes), formatWithUnits(p.Requests), avg}
	})
}
