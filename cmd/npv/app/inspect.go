package app

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
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
	Example          string `json:"example"`
	Identity         int    `json:"identity"`
	WildcardProtocol bool   `json:"wildcard_protocol"`
	WildcardPort     bool   `json:"wildcard_port"`
	Protocol         int    `json:"protocol"`
	Port             int    `json:"port"`
	Bytes            int    `json:"bytes"`
	Packets          int    `json:"packets"`
}

func runInspect(ctx context.Context, w io.Writer, name string) error {
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
				// If the identity is in the local scope, it is only valid on the reporting node.
				params := policy.GetIdentityIDParams{
					Context: ctx,
					ID:      strconv.FormatInt(int64(p.Key.Identity), 10),
				}
				response, err := client.Policy.GetIdentityID(&params)
				if err != nil {
					return fmt.Errorf("failed to get identity: %w", err)
				}
				if slices.Contains(response.Payload.Labels, "reserved:world") {
					// If the identity is a world one, its labels contain multiple nesting CIDRs.
					// For example, 0.0.0.0/0, 0.0.0.0/1, ..., 8.8.8.8/32.
					// The following code finds the smallest CIDR from the list.
					slices.SortFunc(response.Payload.Labels, func(a, b string) int {
						aparts := strings.Split(a, "/")
						bparts := strings.Split(b, "/")
						if len(aparts) < 2 || len(bparts) < 2 {
							return len(bparts) - len(aparts)
						}
						abits, _ := strconv.Atoi(aparts[1])
						bbits, _ := strconv.Atoi(bparts[1])
						return bbits - abits
					})
					entry.Example = response.Payload.Labels[0]
				}
			}
		}
		entry.Identity = p.Key.Identity
		entry.WildcardProtocol = p.IsWildcardProtocol()
		entry.WildcardPort = p.IsWildcardPort()
		entry.Protocol = p.Key.Protocol
		entry.Port = p.Key.Port()
		entry.Bytes = p.Bytes
		entry.Packets = p.Packets
		arr[i] = entry
	}

	// I don't know it is safe to sort the result of "cilium bpf policy get", so let's keep the original order.
	header := []string{"POLICY", "DIRECTION", "IDENTITY", "NAMESPACE", "EXAMPLE", "PROTOCOL", "PORT", "BYTES", "PACKETS"}
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
		return []any{p.Policy, p.Direction, p.Identity, p.Namespace, p.Example, protocol, port, p.Bytes, p.Packets}
	})
}
