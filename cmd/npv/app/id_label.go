package app

import (
	"context"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	idCmd.AddCommand(idLabelCmd)
}

var idLabelCmd = &cobra.Command{
	Use:   "label",
	Short: "Show label cardinarity of CiliumIdentity",
	Long:  `Show label cardinarity of CiliumIdentity`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runIdLabel(context.Background(), cmd.OutOrStdout())
	},
}

func runIdLabel(ctx context.Context, w io.Writer) error {
	_, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	li, err := dynamicClient.Resource(gvrIdentity).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	labelMap := make(map[string][]string)
	for _, item := range li.Items {
		ns, ok, err := unstructured.NestedString(item.Object, "security-labels", "k8s:io.kubernetes.pod.namespace")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if !(rootOptions.allNamespaces || ns == rootOptions.namespace) {
			continue
		}

		labels, _, err := unstructured.NestedStringMap(item.Object, "security-labels")
		if err != nil {
			return err
		}
		for k, v := range labels {
			// These labels do not vary in a single namespace, so their cardinality is always one
			if k == "k8s:io.cilium.k8s.policy.cluster" ||
				k == "k8s:io.kubernetes.pod.namespace" ||
				strings.HasPrefix(k, "k8s:io.cilium.k8s.namespace.labels") {
				continue
			}
			if _, ok := labelMap[k]; !ok {
				labelMap[k] = make([]string, 0, 1)
			}
			labelMap[k] = append(labelMap[k], v)
		}
	}

	for k := range labelMap {
		sort.Strings(labelMap[k])
		labelMap[k] = slices.Compact(labelMap[k])
	}
	keys := slices.Collect(maps.Keys(labelMap))
	sort.Strings(keys)

	return writeSimpleOrJson(w, labelMap, []string{"LABEL", "COUNT", "VALUES"}, len(keys), func(index int) []any {
		k := keys[index]
		li := labelMap[k]
		return []any{k, len(li), strings.Join(li, ",")}
	})
}
