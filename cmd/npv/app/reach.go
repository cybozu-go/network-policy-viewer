package app

import (
	"context"
	"errors"
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
	Role             string `json:"role"`
	Direction        string `json:"direction"`
	Policy           string `json:"policy"`
	Identity         int    `json:"identity"`
	Namespace        string `json:"namespace"`
	Example          string `json:"example_endpoint"`
	WildcardProtocol bool   `json:"wildcard_protocol"`
	WildcardPort     bool   `json:"wildcard_port"`
	Protocol         int    `json:"protocol"`
	Port             int    `json:"port"`
	Bytes            int    `json:"bytes"`
	Requests         int    `json:"requests"`
}

func runReach(ctx context.Context, w io.Writer) error {
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

	ids, err := getIdentityResourceMap(ctx, dynamicClient)
	if err != nil {
		return err
	}

	idEndpoints, err := getIdentityEndpoints(ctx, dynamicClient)
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
		case reachOptions.toCIDR.isSet():
			filter, err = parseCIDROptions(false, true, "to", &reachOptions.toCIDR)
			if err != nil {
				return err
			}
		default:
			return errors.New("one of --to or --to-cidrs must be specified")
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
			entry.Role = trafficRoleSender
			entry.Direction = directionEgress
			if p.IsDenyRule() {
				entry.Policy = policyDeny
			} else {
				entry.Policy = policyAllow
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
		case reachOptions.fromCIDR.isSet():
			filter, err = parseCIDROptions(true, false, "from", &reachOptions.fromCIDR)
			if err != nil {
				return err
			}
		default:
			return errors.New("one of --from or --from-cidrs must be specified")
		}

		client, err := createCiliumClient(ctx, clientset, to.Namespace, to.Name)
		if err != nil {
			return err
		}

		policies, err := queryPolicyMap(ctx, clientset, dynamicClient, to.Namespace, to.Name)
		if err != nil {
			return err
		}
		if policies, err = filterPolicyMap(ctx, client, policies, filter); err != nil {
			return err
		}

		for _, p := range policies {
			var entry reachEntry
			entry.Role = trafficRoleReceiver
			entry.Direction = directionIngress
			if p.IsDenyRule() {
				entry.Policy = policyDeny
			} else {
				entry.Policy = policyAllow
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
			arr = append(arr, entry)
		}
	}

	header := []string{"ROLE", "DIRECTION", "POLICY", "|", "IDENTITY", "NAMESPACE", "EXAMPLE-ENDPOINT", "|", "PROTOCOL", "PORT", "|", "BYTES:", "REQUESTS:", "AVERAGE:"}
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
		return []any{p.Role, p.Direction, p.Policy, "|", p.Identity, p.Namespace, p.Example, "|", protocol, port, "|", formatWithUnits(p.Bytes), formatWithUnits(p.Requests), avg}
	})
}
