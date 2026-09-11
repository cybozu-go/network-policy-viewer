package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cybozu-go/network-policy-viewer/pkg/gvk"
	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
	"github.com/cybozu-go/network-policy-viewer/pkg/output"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

func init() {
	addGroupOption(lookupCmd)
	addPodSelectorOption(lookupCmd)
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
			return runLookup(context.Background(), cmd.OutOrStdout(), "")
		} else {
			return runLookup(context.Background(), cmd.OutOrStdout(), args[0])
		}
	},
	ValidArgsFunction: completePods,
}

type lookupEntry struct {
	Subject   string `json:"subject"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
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
	return x
}

func groupSubjectByIdentities(ctx context.Context, c client.Client, name string) (map[uint32][]*corev1.Pod, error) {
	subjects, err := subject.ListSubjectPods(ctx, c, name)
	if err != nil {
		return nil, err
	}

	ret := make(map[uint32][]*corev1.Pod)
	for _, s := range subjects {
		id, err := getPodIdentity(ctx, c, s.Namespace, s.Name)
		if err != nil {
			return nil, err
		}
		if _, ok := ret[id]; !ok {
			ret[id] = make([]*corev1.Pod, 0)
		}
		ret[id] = append(ret[id], s)
	}
	return ret, nil
}

func lookupIdentities(rule *api.Rule, targets map[uint32]labels.LabelArray) []uint32 {
	ret := make([]uint32, 0)

OUTER:
	for k, v := range targets {
		if rule.EndpointSelector.Matches(v) {
			ret = append(ret, k)
			continue OUTER
		}
		for _, r := range rule.Ingress {
			for _, s := range r.FromEndpoints {
				if s.Matches(v) {
					ret = append(ret, k)
					continue OUTER
				}
			}
		}
		for _, r := range rule.IngressDeny {
			for _, s := range r.FromEndpoints {
				if s.Matches(v) {
					ret = append(ret, k)
					continue OUTER
				}
			}
		}
		for _, r := range rule.Egress {
			for _, s := range r.ToEndpoints {
				if s.Matches(v) {
					ret = append(ret, k)
					continue OUTER
				}
			}
		}
		for _, r := range rule.EgressDeny {
			for _, s := range r.ToEndpoints {
				if s.Matches(v) {
					ret = append(ret, k)
					continue OUTER
				}
			}
		}
	}
	return ret
}

func runLookup(ctx context.Context, stdout io.Writer, name string) error {
	c, err := k8s.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create k8s clients: %w", err)
	}

	idMap, err := getIdentityResourceMap(ctx, c)
	if err != nil {
		return err
	}

	subIDs, err := groupSubjectByIdentities(ctx, c, name)
	if err != nil {
		return err
	}

	subIDLabels := make(map[uint32]labels.LabelArray)
	for id := range subIDs {
		subIDLabels[id] = labels.Map2Labels(idMap[id].SecurityLabels, labels.LabelSourceK8s).LabelArray()
	}

	arr := make([]lookupEntry, 0)
	ccnps := make([]*ciliumv2.CiliumClusterwideNetworkPolicy, 0)
	cnps := make([]*ciliumv2.CiliumNetworkPolicy, 0)

	var ccnpList ciliumv2.CiliumClusterwideNetworkPolicyList
	if err := c.List(ctx, &ccnpList); err != nil {
		return err
	}

ccnpLoop:
	for _, ccnp := range ccnpList.Items {
		rules, err := ccnp.Parse(logging.DefaultSlogLogger, "")
		if err != nil {
			return err
		}

		for _, r := range rules {
			matchIDs := lookupIdentities(r, subIDLabels)
			if commonOptions.manifests {
				if len(matchIDs) > 0 {
					ccnps = append(ccnps, &ccnp)
					continue ccnpLoop
				}
			} else {
				for _, id := range matchIDs {
					for _, p := range subIDs[id] {
						entry := lookupEntry{
							Subject:   subject.GetPodSubject(p.Namespace, p.Name),
							Kind:      gvk.ClusterwideNetworkPolicy.Kind,
							Namespace: "-",
							Name:      ccnp.Name,
						}
						arr = append(arr, entry)
					}
				}
			}
		}
	}

	var cnpList ciliumv2.CiliumNetworkPolicyList
	if err := c.List(ctx, &cnpList); err != nil {
		return err
	}

cnpLoop:
	for _, cnp := range cnpList.Items {
		rules, err := cnp.Parse(logging.DefaultSlogLogger, "")
		if err != nil {
			return err
		}

		for _, r := range rules {
			matchIDs := lookupIdentities(r, subIDLabels)
			if commonOptions.manifests {
				if len(matchIDs) > 0 {
					cnps = append(cnps, &cnp)
					continue cnpLoop
				}
			} else {
				for _, id := range matchIDs {
					for _, p := range subIDs[id] {
						entry := lookupEntry{
							Subject:   subject.GetPodSubject(p.Namespace, p.Name),
							Kind:      gvk.NetworkPolicy.Kind,
							Namespace: cnp.Namespace,
							Name:      cnp.Name,
						}
						arr = append(arr, entry)
					}
				}
			}
		}
	}

	sort.Slice(arr, func(i, j int) bool { return compareLookupEntry(&arr[i], &arr[j]) < 0 })
	arr = compactBy(arr, compareLookupEntry, mergeLookupEntry)

	if commonOptions.manifests {
		return output.WriteManifests(stdout, ccnps, cnps)
	}

	subHeader := []string{"SUBJECT", "|"}
	header := []string{"KIND", "NAMESPACE", "NAME"}
	if subject.ShouldPrintSubject(name) {
		header = append(subHeader, header...)
	}
	return output.WriteSimpleOrJson(stdout, arr, header, len(arr), func(index int) []any {
		p := arr[index]
		subValues := []any{p.Subject, "|"}
		values := []any{p.Kind, p.Namespace, p.Name}
		if subject.ShouldPrintSubject(name) {
			values = append(subValues, values...)
		}
		return values
	})
}
