package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	"github.com/cybozu-go/network-policy-viewer/pkg/gvr"
	"github.com/cybozu-go/network-policy-viewer/pkg/proxy"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

var listOptions struct {
	manifests bool
}

func init() {
	addGroupOption(listCmd)
	addSelectorOption(listCmd)
	addDirectionOption(listCmd)
	listCmd.Flags().BoolVarP(&listOptions.manifests, "manifests", "m", false, "show policy manifests")
	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list network policies applied to a pod",
	Long:  `List network policies applied to a pod`,

	Args: cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return runList(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), "")
		} else {
			return runList(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0])
		}
	},
	ValidArgsFunction: completePods,
}

type listEntry struct {
	Subject   string `json:"subject"`
	Direction string `json:"direction"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func compareListEntry(x, y *listEntry) int {
	ret := strings.Compare(x.Subject, y.Subject)
	if ret == 0 {
		ret = strings.Compare(x.Direction, y.Direction)
	}
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

func mergeListEntry(x, y *listEntry) *listEntry {
	return x
}

func parseListEntry(subject, direction string, input []string) listEntry {
	val := listEntry{
		Subject:   subject,
		Direction: direction,
		Namespace: "-",
	}
	for _, s := range input {
		switch {
		case strings.Contains(s, "k8s:io.cilium.k8s.policy.derived-from"):
			val.Kind = strings.Split(s, "=")[1]
		case strings.Contains(s, "k8s:io.cilium.k8s.policy.namespace"):
			val.Namespace = strings.Split(s, "=")[1]
		case strings.Contains(s, "k8s:io.cilium.k8s.policy.name"):
			val.Name = strings.Split(s, "=")[1]
		}
	}
	return val
}

func runListOnPod(ctx context.Context, stderr io.Writer, clientset *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, pod *corev1.Pod) ([]listEntry, error) {
	policySet := make(map[listEntry]any)

	client, err := proxy.CreateCiliumClient(ctx, stderr, clientset, dynamicClient, pod.Namespace, pod.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cilium client: %w", err)
	}

	response, err := client.GetEndpointResponse(ctx, pod.Namespace, pod.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoint info: %w", err)
	}

	if policyOptions.ingress {
		ingressRules := response.Payload.Status.Policy.Realized.L4.Ingress
		for _, rule := range ingressRules {
			for _, r := range rule.DerivedFromRules {
				entry := parseListEntry(subject.GetPodSubject(pod.Namespace, pod.Name), directionIngress, r)
				policySet[entry] = struct{}{}
			}
		}
	}
	if policyOptions.egress {
		egressRules := response.Payload.Status.Policy.Realized.L4.Egress
		for _, rule := range egressRules {
			for _, r := range rule.DerivedFromRules {
				entry := parseListEntry(subject.GetPodSubject(pod.Namespace, pod.Name), directionEgress, r)
				policySet[entry] = struct{}{}
			}
		}
	}

	policyList := slices.Collect(maps.Keys(policySet))
	sort.Slice(policyList, func(i, j int) bool { return compareListEntry(&policyList[i], &policyList[j]) < 0 })
	return policyList, nil
}

func runList(ctx context.Context, stdout, stderr io.Writer, name string) error {
	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return fmt.Errorf("failed to create k8s clients: %w", err)
	}

	pods, err := subject.ListSubjectPods(ctx, clientset, name)
	if err != nil {
		return err
	}

	// The same rule appears multiple times in the response, so we need to dedup it
	arr := mapNodeReduce(pods,
		func() []listEntry {
			return make([]listEntry, 0)
		},
		func(pod *corev1.Pod) []listEntry {
			policy, err := runListOnPod(ctx, stderr, clientset, dynamicClient, pod)
			if err != nil {
				fmt.Fprintf(stderr, "Warning: %v\n", err)
				return nil
			}
			return policy
		},
		func(x, y []listEntry) []listEntry {
			return mergeBy(x, y, compareListEntry, mergeListEntry)
		},
	)

	if listOptions.manifests {
		return listPolicyManifests(ctx, stdout, dynamicClient, arr)
	}

	subHeader := []string{"SUBJECT", "|"}
	header := []string{"DIRECTION", "|", "KIND", "NAMESPACE", "NAME"}
	if shouldPrintSubject(name) {
		header = append(subHeader, header...)
	}
	return writeSimpleOrJson(stdout, arr, header, len(arr), func(index int) []any {
		p := arr[index]
		subValues := []any{p.Subject, "|"}
		values := []any{p.Direction, "|", p.Kind, p.Namespace, p.Name}
		if shouldPrintSubject(name) {
			values = append(subValues, values...)
		}
		return values
	})
}

func listPolicyManifests(ctx context.Context, w io.Writer, dynamicClient *dynamic.DynamicClient, policyList []listEntry) error {
	// remove direction info and sort again
	for i := range policyList {
		policyList[i].Direction = ""
	}
	sort.Slice(policyList, func(i, j int) bool { return compareListEntry(&policyList[i], &policyList[j]) < 0 })

	var previous types.NamespacedName
	first := true
	for _, p := range policyList {
		// a same policy may appear twice from egress and ingress rules, so we need to dedup them
		next := types.NamespacedName{
			Namespace: p.Namespace,
			Name:      p.Name,
		}
		if previous == next {
			continue
		}
		previous = next

		if !first {
			if _, err := fmt.Fprintln(w, "---"); err != nil {
				return err
			}
		}
		first = false

		isCNP := p.Kind == "CiliumNetworkPolicy"
		var resource *unstructured.Unstructured
		if isCNP {
			cnp, err := dynamicClient.Resource(gvr.NetworkPolicy).Namespace(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			resource = cnp
		} else {
			ccnp, err := dynamicClient.Resource(gvr.ClusterwideNetworkPolicy).Get(ctx, p.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			resource = ccnp
		}
		unstructured.RemoveNestedField(resource.Object, "metadata", "annotations", "kubectl.kubernetes.io/last-applied-configuration")
		unstructured.RemoveNestedField(resource.Object, "metadata", "creationTimestamp")
		unstructured.RemoveNestedField(resource.Object, "metadata", "generation")
		unstructured.RemoveNestedField(resource.Object, "metadata", "managedFields")
		unstructured.RemoveNestedField(resource.Object, "metadata", "resourceVersion")
		unstructured.RemoveNestedField(resource.Object, "metadata", "uid")
		unstructured.RemoveNestedField(resource.Object, "status")

		data, err := yaml.Marshal(resource.Object)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s", string(data)); err != nil {
			return err
		}
	}
	return nil
}
