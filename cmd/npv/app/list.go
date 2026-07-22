package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cybozu-go/network-policy-viewer/pkg/gvk"
	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
	"github.com/cybozu-go/network-policy-viewer/pkg/output"
	"github.com/cybozu-go/network-policy-viewer/pkg/proxy"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

func init() {
	addGroupOption(listCmd)
	addPodSelectorOption(listCmd)
	addDirectionOption(listCmd)
	addManifestOption(listCmd)
	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List network policies applied to a pod",
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
	if commonOptions.manifests {
		val.Direction = ""
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

func runListOnPod(ctx context.Context, stderr io.Writer, c client.Client, pod *corev1.Pod) ([]listEntry, error) {
	policySet := make(map[listEntry]any)

	client, err := proxy.CreateCiliumClient(ctx, stderr, c, pod.Namespace, pod.Name)
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
	c, err := k8s.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create k8s clients: %w", err)
	}

	pods, err := subject.ListSubjectPods(ctx, c, name)
	if err != nil {
		return err
	}

	// The same rule appears multiple times in the response, so we need to dedup it
	arr := mapNodeReduce(pods,
		func() []listEntry {
			return make([]listEntry, 0)
		},
		func(pod *corev1.Pod) []listEntry {
			policy, err := runListOnPod(ctx, stderr, c, pod)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "Warning: %v\n", err)
				return nil
			}
			return policy
		},
		func(x, y []listEntry) []listEntry {
			return mergeBy(x, y, compareListEntry, mergeListEntry)
		},
	)

	if commonOptions.manifests {
		ccnps := make([]*ciliumv2.CiliumClusterwideNetworkPolicy, 0)
		cnps := make([]*ciliumv2.CiliumNetworkPolicy, 0)
		for _, p := range arr {
			if p.Kind == gvk.ClusterwideNetworkPolicy.Kind {
				var ccnp ciliumv2.CiliumClusterwideNetworkPolicy
				if err := c.Get(ctx, types.NamespacedName{Name: p.Name}, &ccnp); err != nil {
					return err
				}
				ccnps = append(ccnps, &ccnp)
			} else {
				var cnp ciliumv2.CiliumNetworkPolicy
				if err := c.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Name}, &cnp); err != nil {
					return err
				}
				cnps = append(cnps, &cnp)
			}
		}
		return output.WriteManifests(stdout, ccnps, cnps)
	}

	subHeader := []string{"SUBJECT", "|"}
	header := []string{"DIRECTION", "|", "KIND", "NAMESPACE", "NAME"}
	if subject.ShouldPrintSubject(name) {
		header = append(subHeader, header...)
	}
	return output.WriteSimpleOrJson(stdout, arr, header, len(arr), func(index int) []any {
		p := arr[index]
		subValues := []any{p.Subject, "|"}
		values := []any{p.Direction, "|", p.Kind, p.Namespace, p.Name}
		if subject.ShouldPrintSubject(name) {
			values = append(subValues, values...)
		}
		return values
	})
}
