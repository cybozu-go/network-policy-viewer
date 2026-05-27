package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/cybozu-go/network-policy-viewer/pkg/cidr"
)

var inspectOptions struct {
	allowed   bool
	denied    bool
	used      bool
	unused    bool
	maskCIDRs bool
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectOptions.allowed, "allowed", false, "show allowed-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.denied, "denied", false, "show denied-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.used, "used", false, "show used-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.unused, "unused", false, "show unused-rules only")
	inspectCmd.Flags().BoolVar(&inspectOptions.maskCIDRs, "mask-cidrs", false, "mask cluster-external CIDRs and unify them into public, private, and unknown")
	addGroupOption(inspectCmd)
	addSelectorOption(inspectCmd)
	addWithCIDROptions(inspectCmd)
	addDirectionOption(inspectCmd)
	rootCmd.AddCommand(inspectCmd)
}

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect network policies of selected pods",
	Long:  `Inspect network policies of selected pods`,

	Args: cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return runInspect(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), "")
		} else {
			return runInspect(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0])
		}
	},
	ValidArgsFunction: completePods,
}

// This command aims to show the result of "cilium bpf policy get" from a remote pod.
// https://github.com/cilium/cilium/blob/v1.16.3/cilium-dbg/cmd/bpf_policy_get.go
type inspectEntry struct {
	Subject          string `json:"subject"`
	Policy           string `json:"policy"`
	Direction        string `json:"direction"`
	Namespace        string `json:"namespace"`
	Example          string `json:"example_endpoint"`
	Identity         uint32 `json:"identity"`
	WildcardProtocol bool   `json:"wildcard_protocol"`
	WildcardPort     bool   `json:"wildcard_port"`
	Protocol         uint8  `json:"protocol"`
	Port             uint16 `json:"port"`
	Bytes            uint64 `json:"bytes"`
	Requests         uint64 `json:"requests"`
}

func compareInspectEntry(x, y *inspectEntry) int {
	ret := strings.Compare(x.Subject, y.Subject)
	if ret == 0 {
		// List Deny first
		ret = -strings.Compare(x.Policy, y.Policy)
	}
	if ret == 0 {
		// List Ingress first
		ret = -strings.Compare(x.Direction, y.Direction)
	}
	if ret == 0 {
		ret = strings.Compare(x.Namespace, y.Namespace)
	}
	if ret == 0 {
		ret = strings.Compare(x.Example, y.Example)
	}
	if ret == 0 {
		ret = int(x.Protocol) - int(y.Protocol)
	}
	if ret == 0 {
		ret = int(x.Port) - int(y.Port)
	}
	return ret
}

func mergeInspectEntry(x, y *inspectEntry) *inspectEntry {
	x.Bytes += y.Bytes
	x.Requests += y.Requests
	return x
}

func parseInspectOptions() {
	if !inspectOptions.allowed && !inspectOptions.denied {
		inspectOptions.allowed = true
		inspectOptions.denied = true
	}
	if !inspectOptions.used && !inspectOptions.unused {
		inspectOptions.used = true
		inspectOptions.unused = true
	}
}

func runInspectOnPod(ctx context.Context, stderr io.Writer, clientset *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, filter policyFilter, pod *corev1.Pod) ([]inspectEntry, error) {
	client, err := createCiliumClient(ctx, stderr, clientset, pod.Namespace, pod.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cilium client: %w", err)
	}

	ids, err := getIdentityResourceMap(ctx, dynamicClient)
	if err != nil {
		return nil, err
	}

	policies, err := queryPolicyMap(ctx, clientset, dynamicClient, pod.Namespace, pod.Name)
	if err != nil {
		return nil, err
	}
	if policies, err = filterPolicyMap(ctx, client, policies, filter); err != nil {
		return nil, err
	}

	arr := make([]inspectEntry, len(policies))
	for i, p := range policies {
		var entry inspectEntry
		entry.Subject = getPodSubject(pod)
		if p.IsDeny() {
			entry.Policy = policyDeny
		} else {
			entry.Policy = policyAllow
		}
		if p.IsEgress() {
			entry.Direction = directionEgress
		} else {
			entry.Direction = directionIngress
		}
		entry.Namespace = "-"
		if id, ok := ids[p.Key.Identity]; ok {
			ns, ok, err := unstructured.NestedString(id.Object, "security-labels", "k8s:io.kubernetes.pod.namespace")
			if err != nil {
				return nil, err
			}
			if ok {
				entry.Namespace = ns
			}
		}
		entry.Example = "-"
		entry.Identity = p.Key.Identity
		example, err := getIdentityExample(ctx, dynamicClient, p.Key.Identity)
		if err != nil {
			return nil, err
		}
		if example != nil {
			entry.Example = example.GetName()
		} else {
			idObj := identity.NumericIdentity(p.Key.Identity)
			if idObj.IsReservedIdentity() {
				entry.Example = "reserved:" + idObj.String()
			} else if idObj.HasLocalScope() {
				c, err := client.getCIDRForIdentity(ctx, p.Key.Identity)
				if err != nil {
					return nil, err
				}
				if inspectOptions.maskCIDRs {
					var expr string
					switch {
					case cidr.IsPrivateCIDR(c):
						expr = "private"
					case cidr.IsPublicCIDR(c):
						expr = "public"
					default:
						expr = "unknown"
					}
					entry.Identity = uint32(identity.ReservedIdentityWorld)
					entry.Example = fmt.Sprintf("cidr:%s", expr)
				} else {
					entry.Example = "cidr:" + c.String()
				}
			}
		}
		entry.WildcardProtocol = p.IsWildcardProtocol()
		entry.WildcardPort = p.IsWildcardPort()
		entry.Protocol = p.GetProtocol()
		entry.Port = p.Key.GetDestPort()
		entry.Bytes = p.Bytes
		entry.Requests = p.Packets
		arr[i] = entry
	}
	return arr, nil
}

func runInspect(ctx context.Context, stdout, stderr io.Writer, name string) error {
	if err := validateGroupOption(); err != nil {
		return err
	}
	parseInspectOptions()
	basicFilter := makeBasicFilter(
		policyOptions.ingress, policyOptions.egress,
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

	pods, err := selectSubjectPods(ctx, clientset, name, commonOptions.selector)
	if err != nil {
		return err
	}

	arr := mapNodeReduce(pods,
		func() []inspectEntry {
			return make([]inspectEntry, 0)
		},
		func(pod *corev1.Pod) []inspectEntry {
			result, err := runInspectOnPod(ctx, stderr, clientset, dynamicClient, filter, pod)
			if err != nil {
				fmt.Fprintf(stderr, "Warning: %v\n", err)
				return nil
			}
			sort.Slice(result, func(i, j int) bool { return compareInspectEntry(&result[i], &result[j]) < 0 })
			return compactBy(result, compareInspectEntry, mergeInspectEntry)
		},
		func(x, y []inspectEntry) []inspectEntry {
			return mergeBy(x, y, compareInspectEntry, mergeInspectEntry)
		},
	)

	subHeader := []string{"SUBJECT", "|"}
	header := []string{"POLICY", "DIRECTION", "|", "IDENTITY", "NAMESPACE", "EXAMPLE-ENDPOINT", "|", "PROTOCOL", "PORT", "|", "BYTES:", "REQUESTS:", "AVERAGE:"}
	if shouldPrintSubject(name) {
		header = append(subHeader, header...)
	}
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
		subValues := []any{p.Subject, "|"}
		values := []any{p.Policy, p.Direction, "|", p.Identity, p.Namespace, p.Example, "|", protocol, port, "|", formatWithUnits(p.Bytes), formatWithUnits(p.Requests), avg}
		if shouldPrintSubject(name) {
			values = append(subValues, values...)
		}
		return values
	})
}
