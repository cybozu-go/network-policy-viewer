package app

import (
	"context"
	"io"
	"maps"
	"slices"
	"sort"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	idCmd.AddCommand(idSummaryCmd)
}

var idSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Count CiliumIdentity by namespace",
	Long:  `Count CiliumIdentity by namespace`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runIdSummary(context.Background(), cmd.OutOrStdout())
	},
}

func runIdSummary(ctx context.Context, w io.Writer) error {
	_, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	li, err := dynamicClient.Resource(gvrIdentity).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	countMap := make(map[string]int)
	for _, item := range li.Items {
		ns, ok, err := unstructured.NestedString(item.Object, "security-labels", "k8s:io.kubernetes.pod.namespace")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		countMap[ns] += 1
	}

	keys := slices.Collect(maps.Keys(countMap))
	sort.Strings(keys)

	return writeSimpleOrJson(w, countMap, []string{"NAMESPACE", "IDENTITY"}, len(keys), func(index int) []any {
		k := keys[index]
		return []any{k, countMap[k]}
	})
}
