package sub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var inspectOptions struct {
	prefix bool
}

func init() {
	inspectCmd.Flags().BoolVarP(&inspectOptions.prefix, "prefix", "p", false, "search pod with specified prefix")
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
}

type policyEntryKey struct {
	Identity  int `json:"Identity"`
	Direction int `json:"TrafficDirection"`
	Protocol  int `json:"Nexthdr"`
	BigPort   int `json:"DestPortNetwork"` // big endian
}

// For the meanings of the flags, see:
// https://github.com/cilium/cilium/blob/v1.16.3/bpf/lib/common.h#L394
type policyEntry struct {
	Flags   int            `json:"Flags"`
	Packets int            `json:"Packets"`
	Bytes   int            `json:"Bytes"`
	Key     policyEntryKey `json:"Key"`
}

func (p policyEntry) IsDenyRule() bool {
	return (p.Flags & 1) > 0
}

func (p policyEntry) IsEgressRule() bool {
	return p.Key.Direction > 0
}

func (p policyEntry) IsWildcardProtocol() bool {
	return (p.Flags & 2) > 0
}

func (p policyEntry) IsWildcardPort() bool {
	return (p.Flags & 4) > 0
}

// This command aims to show the result of "cilium bpf policy get" from a remote pod.
// https://github.com/cilium/cilium/blob/v1.16.3/cilium-dbg/cmd/bpf_policy_get.go
type inspectEntry struct {
	Policy           string `json:"policy"`
	Direction        string `json:"direction"`
	Namespace        string `json:"namespace"`
	Identity         int    `json:"identity"`
	WildcardProtocol bool   `json:"wildcard_protocol"`
	WildcardPort     bool   `json:"wildcard_port"`
	Protocol         int    `json:"protocol"`
	Port             int    `json:"port"`
	Bytes            int    `json:"bytes"`
	Packets          int    `json:"packets"`
}

func queryPolicyMap(ctx context.Context, clientset *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, namespace, name string) ([]policyEntry, error) {
	endpointID, err := getPodEndpointID(ctx, dynamicClient, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod endpoint ID: %w", err)
	}

	url, err := getProxyEndpoint(ctx, clientset, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy endpoint: %w", err)
	}

	url = fmt.Sprintf("%s/policy/%d", url, endpointID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to request policy: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	policies := make([]policyEntry, 0)
	if err = json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return policies, nil
}

func runInspect(ctx context.Context, w io.Writer, name string) error {
	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	if inspectOptions.prefix {
		pods, err := clientset.CoreV1().Pods(rootOptions.namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil
		}
		found := false
		prefix := name
		for _, p := range pods.Items {
			if strings.HasPrefix(p.GetName(), prefix) {
				if found {
					return errors.New("multiple pods found for the prefix: " + prefix)
				}
				found = true
				name = p.GetName()
			}
		}
	}

	policies, err := queryPolicyMap(ctx, clientset, dynamicClient, rootOptions.namespace, name)
	if err != nil {
		return err
	}

	ids, err := getIdentityMap(ctx, dynamicClient)
	if err != nil {
		return err
	}

	examples, err := getIdentityExampleMap(ctx, dynamicClient)
	if err != nil {
		return err
	}

	arr := make([]inspectEntry, len(policies))
	for i, policy := range policies {
		var entry inspectEntry
		if policy.IsDenyRule() {
			entry.Policy = policyDeny
		} else {
			entry.Policy = policyAllow
		}
		if policy.IsEgressRule() {
			entry.Direction = directionEgress
		} else {
			entry.Direction = directionIngress
		}
		entry.Namespace = "-"
		if id, ok := ids[policy.Key.Identity]; ok {
			ns, ok, err := unstructured.NestedString(id.Object, "security-labels", "k8s:io.kubernetes.pod.namespace")
			if err != nil {
				return err
			}
			if ok {
				entry.Namespace = ns
			}
		}
		entry.Identity = policy.Key.Identity
		entry.WildcardProtocol = policy.IsWildcardProtocol()
		entry.WildcardPort = policy.IsWildcardPort()
		entry.Protocol = policy.Key.Protocol
		entry.Port = ((policy.Key.BigPort & 0xFF) << 8) + ((policy.Key.BigPort & 0xFF00) >> 8)
		entry.Bytes = policy.Bytes
		entry.Packets = policy.Packets
		arr[i] = entry
	}

	switch rootOptions.output {
	case OutputJson:
		text, err := json.MarshalIndent(arr, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(text)
		return err
	case OutputSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		if !rootOptions.noHeaders {
			if _, err := tw.Write([]byte("POLICY\tDIRECTION\tIDENTITY\tNAMESPACE\tEXAMPLE\tPROTOCOL\tPORT\tBYTES\tPACKETS\n")); err != nil {
				return err
			}
		}
		for _, p := range arr {
			var example, protocol, port string
			if v, ok := examples[p.Identity]; ok {
				example = v
			} else {
				idObj := identity.NumericIdentity(p.Identity)
				if idObj.IsReservedIdentity() {
					example = "reserved:" + idObj.String()
				}
			}
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
			if _, err := tw.Write([]byte(fmt.Sprintf("%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\n", p.Policy, p.Direction, p.Identity, p.Namespace, example, protocol, port, p.Bytes, p.Packets))); err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
