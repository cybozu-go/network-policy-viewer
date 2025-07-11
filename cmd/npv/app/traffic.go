package app

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var trafficOptions struct {
	selector string
}

func init() {
	trafficCmd.Flags().StringVarP(&trafficOptions.selector, "selector", "l", "", "specify label constraints")
	addWithCIDROptions(trafficCmd)
	rootCmd.AddCommand(trafficCmd)
}

var trafficCmd = &cobra.Command{
	Use:   "traffic",
	Short: "Show traffic amount of selected pods",
	Long:  `Show traffic amount of selected pods`,

	Args: cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return runTraffic(context.Background(), cmd.OutOrStdout(), "")
		} else {
			return runTraffic(context.Background(), cmd.OutOrStdout(), args[0])
		}
	},
	ValidArgsFunction: completePods,
}

type trafficKey struct {
	Direction        string `json:"direction"`
	Identity         int    `json:"identity"`
	Namespace        string `json:"namespace"`
	CIDR             string `json:"cidr"`
	WildcardProtocol bool   `json:"wildcard_protocol"`
	WildcardPort     bool   `json:"wildcard_port"`
	Protocol         int    `json:"protocol"`
	Port             int    `json:"port"`
}

type trafficValue struct {
	Example  string `json:"example_endpoint"`
	Bytes    int    `json:"bytes"`
	Requests int    `json:"requests"`
}

type trafficEntry struct {
	trafficKey
	trafficValue
}

func lessTrafficEntry(x, y *trafficEntry) bool {
	ret := strings.Compare(x.Direction, y.Direction)
	if ret == 0 {
		ret = strings.Compare(x.Namespace, y.Namespace)
	}
	if ret == 0 {
		ret = x.Identity - y.Identity
	}
	if ret == 0 {
		ret = strings.Compare(x.CIDR, y.CIDR)
	}
	return ret < 0
}

func runTraffic(ctx context.Context, w io.Writer, name string) error {
	filter, err := parseCIDROptions(true, true, "with", &commonOptions.with)
	if err != nil {
		return err
	}

	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	pods, err := selectSubjectPods(ctx, clientset, name, trafficOptions.selector)
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

	traffic := make(map[trafficKey]*trafficValue)
	for _, p := range pods {
		client, err := createCiliumClient(ctx, clientset, p.Namespace, p.Name)
		if err != nil {
			return fmt.Errorf("failed to create Cilium client: %w", err)
		}

		policies, err := queryPolicyMap(ctx, clientset, dynamicClient, p.Namespace, p.Name)
		if err != nil {
			return err
		}
		if policies, err = filterPolicyMap(ctx, client, policies, filter); err != nil {
			return err
		}

		for _, p := range policies {
			if (p.Packets == 0) || p.IsDenyRule() {
				continue
			}

			var k trafficKey
			if p.IsEgressRule() {
				k.Direction = directionEgress
			} else {
				k.Direction = directionIngress
			}

			k.Namespace = "-"
			if id, ok := ids[p.Key.Identity]; ok {
				ns, ok, err := unstructured.NestedString(id.Object, "security-labels", "k8s:io.kubernetes.pod.namespace")
				if err != nil {
					return err
				}
				if ok {
					k.Namespace = ns
				}
			}

			k.Identity = p.Key.Identity
			example := "-"
			if v, ok := idEndpoints[p.Key.Identity]; ok {
				i := rand.IntN(len(v))
				example = v[i].GetName()
			} else {
				idObj := identity.NumericIdentity(p.Key.Identity)
				if idObj.IsReservedIdentity() {
					example = "reserved:" + idObj.String()
				} else if idObj.HasLocalScope() {
					response, err := queryLocalIdentity(ctx, client, p.Key.Identity)
					if err != nil {
						return err
					}
					if slices.Contains(response.Payload.Labels, "reserved:world") {
						lbls := labels.NewLabelsFromModel(response.Payload.Labels)
						cidrModel := lbls.GetFromSource(labels.LabelSourceCIDR).GetPrintableModel()
						if len(cidrModel) == 1 {
							// Cilium allocates different identity for a CIDR between nodes, so we cannot use it as a key.
							// Instead, npv shows traffic as belonging to the world identity and differentiate it using CIDR.
							k.Identity = int(identity.ReservedIdentityWorld)
							k.CIDR = strings.Split(cidrModel[0], ":")[1]
							example = cidrModel[0]
						}
					}
				}
			}

			k.WildcardProtocol = p.IsWildcardProtocol()
			k.WildcardPort = p.IsWildcardPort()
			k.Protocol = p.Key.Protocol
			k.Port = p.Key.Port()

			if _, ok := traffic[k]; ok {
				traffic[k].Bytes += p.Bytes
				traffic[k].Requests += p.Packets
			} else {
				traffic[k] = &trafficValue{
					Example:  example,
					Bytes:    p.Bytes,
					Requests: p.Packets,
				}
			}
		}
	}

	arr := make([]trafficEntry, 0)
	for k, v := range traffic {
		arr = append(arr, trafficEntry{k, *v})
	}
	sort.Slice(arr, func(i, j int) bool { return lessTrafficEntry(&arr[i], &arr[j]) })

	header := []string{"DIRECTION", "|", "IDENTITY", "NAMESPACE", "EXAMPLE-ENDPOINT", "|", "PROTOCOL", "PORT", "|", "BYTES:", "REQUESTS:", "AVERAGE:"}
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
		return []any{p.Direction, "|", p.Identity, p.Namespace, p.Example, "|", protocol, port, "|", formatWithUnits(p.Bytes), formatWithUnits(p.Requests), avg}
	})
}
