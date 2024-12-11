package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

var listOptions struct {
	manifests bool
}

func init() {
	listCmd.Flags().BoolVarP(&listOptions.manifests, "manifests", "m", false, "show policy manifests")
	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list network policies applied to a pod",
	Long:  `List network policies applied to a pod`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runList(context.Background(), cmd.OutOrStdout(), args[0])
	},
	ValidArgsFunction: completePods,
}

type derivedFromEntry struct {
	Direction string `json:"direction"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func lessDerivedFromEntry(x, y *derivedFromEntry) bool {
	ret := strings.Compare(x.Direction, y.Direction)
	if ret == 0 {
		ret = strings.Compare(x.Kind, y.Kind)
	}
	if ret == 0 {
		ret = strings.Compare(x.Namespace, y.Namespace)
	}
	if ret == 0 {
		ret = strings.Compare(x.Name, y.Name)
	}
	return ret < 0
}

func parseDerivedFromEntry(input []string, direction string) derivedFromEntry {
	val := derivedFromEntry{
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

func runList(ctx context.Context, w io.Writer, name string) error {
	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return fmt.Errorf("failed to create k8s clients: %w", err)
	}

	client, err := createCiliumClient(ctx, clientset, rootOptions.namespace, name)
	if err != nil {
		return fmt.Errorf("failed to create Cilium client: %w", err)
	}

	endpointID, err := getPodEndpointID(ctx, dynamicClient, rootOptions.namespace, name)
	if err != nil {
		return fmt.Errorf("failed to get pod endpoint ID: %w", err)
	}

	params := endpoint.GetEndpointIDParams{
		Context: ctx,
		ID:      strconv.FormatInt(endpointID, 10),
	}
	response, err := client.Endpoint.GetEndpointID(&params)
	if err != nil {
		return fmt.Errorf("failed to get endpoint information: %w", err)
	}
	if response.Payload == nil ||
		response.Payload.Status == nil ||
		response.Payload.Status.Policy == nil ||
		response.Payload.Status.Policy.Realized == nil ||
		response.Payload.Status.Policy.Realized.L4 == nil ||
		response.Payload.Status.Policy.Realized.L4.Ingress == nil ||
		response.Payload.Status.Policy.Realized.L4.Egress == nil {
		return errors.New("api response is insufficient")
	}

	// The same rule appears multiple times in the response, so we need to dedup it
	policySet := make(map[derivedFromEntry]struct{})

	ingressRules := response.Payload.Status.Policy.Realized.L4.Ingress
	for _, rule := range ingressRules {
		for _, r := range rule.DerivedFromRules {
			entry := parseDerivedFromEntry(r, directionIngress)
			policySet[entry] = struct{}{}
		}
	}

	egressRules := response.Payload.Status.Policy.Realized.L4.Egress
	for _, rule := range egressRules {
		for _, r := range rule.DerivedFromRules {
			entry := parseDerivedFromEntry(r, directionEgress)
			policySet[entry] = struct{}{}
		}
	}

	policyList := maps.Keys(policySet)
	sort.Slice(policyList, func(i, j int) bool { return lessDerivedFromEntry(&policyList[i], &policyList[j]) })

	if listOptions.manifests {
		return listPolicyManifests(ctx, w, dynamicClient, policyList)
	}

	return writeSimpleOrJson(w, policyList, []string{"DIRECTION", "KIND", "NAMESPACE", "NAME"}, len(policyList), func(index int) []any {
		p := policyList[index]
		return []any{p.Direction, p.Kind, p.Namespace, p.Name}
	})
}

func listPolicyManifests(ctx context.Context, w io.Writer, dynamicClient *dynamic.DynamicClient, policyList []derivedFromEntry) error {
	// remove direction info and sort again
	for i := range policyList {
		policyList[i].Direction = ""
	}
	sort.Slice(policyList, func(i, j int) bool { return lessDerivedFromEntry(&policyList[i], &policyList[j]) })

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
			cnp, err := dynamicClient.Resource(gvrNetworkPolicy).Namespace(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			resource = cnp
		} else {
			ccnp, err := dynamicClient.Resource(gvrClusterwideNetworkPolicy).Get(ctx, p.Name, metav1.GetOptions{})
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
