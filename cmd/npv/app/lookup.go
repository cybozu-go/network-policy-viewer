package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/cybozu-go/network-policy-viewer/pkg/gvk"
	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
	"github.com/cybozu-go/network-policy-viewer/pkg/proxy"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

func init() {
	addGroupOption(lookupCmd)
	addPodSelectorOption(lookupCmd)
	addDirectionOption(lookupCmd)
	addManifestOption(lookupCmd)
	rootCmd.AddCommand(lookupCmd)
}

var lookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Lookup all network policies referencing a pod",
	Long:  `Lookup all network policies referencing a pod`,

	Args: cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return runLookup(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), "")
		} else {
			return runLookup(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0])
		}
	},
	ValidArgsFunction: completePods,
}

type lookupEntry struct {
	Subject    string   `json:"subject"`
	Kind       string   `json:"kind"`
	Namespace  string   `json:"namespace"`
	Name       string   `json:"name"`
	Identities []uint32 `json:"identities"`
}

func compareLookupEntry(x, y *lookupEntry) int {
	ret := strings.Compare(x.Subject, y.Subject)
	if ret == 0 {
		ret = strings.Compare(x.Kind, y.Kind)
	}
	if ret == 0 {
		ret = strings.Compare(x.Namespace, y.Namespace)
	}
	if ret == 0 {
		ret = strings.Compare(x.Name, y.Name)
	}
	return ret
}

func mergeLookupEntry(x, y *lookupEntry) *lookupEntry {
	x.Identities = append(x.Identities, y.Identities...)
	slices.Sort(x.Identities)
	x.Identities = slices.Compact(x.Identities)
	return x
}

func runLookupOnPod(ctx context.Context, stderr io.Writer, clientset *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, pod *corev1.Pod) ([]lookupEntry, error) {
	client, err := proxy.CreateCiliumClient(ctx, stderr, clientset, dynamicClient, pod.Namespace, pod.Name)
	if err != nil {
		return nil, err
	}

	// From Cilium 1.19, we need to check subject selector too.
	// https://github.com/cilium/cilium/tree/v1.19/api/v1/client/policy
	response, err := client.GetPolicySelectorResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy selector information: %w", err)
	}

	arr := make([]lookupEntry, 0)
	for _, selector := range response.Payload {
		var kind, ns, name string
		for _, l := range selector.Labels {
			switch l.Key {
			case ciliumio.PolicyLabelDerivedFrom:
				kind = l.Value
			case ciliumio.PolicyLabelNamespace:
				ns = l.Value
			case ciliumio.PolicyLabelName:
				name = l.Value
			}
		}
		switch {
		case kind == "" || name == "":
			return nil, fmt.Errorf("failed to parse selector owner. kind: %s, namespace: %s, name: %s", kind, ns, name)
		case kind == gvk.NetworkPolicy.Kind && ns == "":
			return nil, fmt.Errorf("failed to read namespace for CiliumNetworkPolicy: %s", name)
		}

		entry := lookupEntry{
			Kind:       kind,
			Namespace:  ns,
			Name:       name,
			Identities: make([]uint32, 0),
		}
		for _, id := range selector.Identities {
			idObj := identity.NumericIdentity(id)
			if idObj.IsCluster() {
				entry.Identities = append(entry.Identities, uint32(id))
			}
		}
		arr = append(arr, entry)
	}

	sort.Slice(arr, func(i, j int) bool { return compareLookupEntry(&arr[i], &arr[j]) < 0 })
	return compactBy(arr, compareLookupEntry, mergeLookupEntry), nil
}

func runLookup(ctx context.Context, stdout, stderr io.Writer, name string) error {
	clientset, dynamicClient, err := k8s.CreateClients()
	if err != nil {
		return fmt.Errorf("failed to create k8s clients: %w", err)
	}

	subjects, err := subject.ListSubjectPods(ctx, clientset, name)
	if err != nil {
		return err
	}

	subIDMap := make(map[uint32]any)
	for _, s := range subjects {
		id, err := getPodIdentity(ctx, dynamicClient, s.Namespace, s.Name)
		if err != nil {
			return err
		}
		subIDMap[id] = struct{}{}
	}

	subIDList := slices.Collect(maps.Keys(subIDMap))
	slices.Sort(subIDList)

	proxies, err := proxy.GetProxyPods(ctx, clientset)
	if err != nil {
		return err
	}

	arr := mapNodeReduce(proxies,
		func() []lookupEntry {
			return make([]lookupEntry, 0)
		},
		func(pod *corev1.Pod) []lookupEntry {
			li, err := runLookupOnPod(ctx, stderr, clientset, dynamicClient, pod)
			if err != nil {
				fmt.Fprintf(stderr, "Warning: %v\n", err)
				return nil
			}
			return li
		},
		func(x, y []lookupEntry) []lookupEntry {
			return mergeBy(x, y, compareLookupEntry, mergeLookupEntry)
		},
	)

	arr = slices.DeleteFunc(arr, func(entry lookupEntry) bool {
		i, j := 0, 0
		for i < len(subIDList) && j < len(entry.Identities) {
			if subIDList[i] == entry.Identities[j] {
				return false
			}
			if subIDList[i] < entry.Identities[j] {
				i++
			} else {
				j++
			}
		}
		return true
	})

	header := []string{"KIND", "NAMESPACE", "NAME"}
	return writeSimpleOrJson(stdout, arr, header, len(arr), func(index int) []any {
		p := arr[index]
		if p.Namespace == "" {
			p.Namespace = "-"
		}
		return []any{p.Kind, p.Namespace, p.Name}
	})
}
