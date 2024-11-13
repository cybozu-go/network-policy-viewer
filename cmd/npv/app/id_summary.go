package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"text/tabwriter"

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
			return fmt.Errorf("CiliumIdentity resource should have namespace label: %s", item.GetName())
		}
		countMap[ns] += 1
	}

	keys := slices.Collect(maps.Keys(countMap))
	sort.Strings(keys)

	switch rootOptions.output {
	case OutputJson:
		text, err := json.MarshalIndent(countMap, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(text)
		return err
	case OutputSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		if !rootOptions.noHeaders {
			if _, err := tw.Write([]byte("NAMESPACE\tIDENTITY\n")); err != nil {
				return err
			}
		}
		for _, k := range keys {
			if _, err := tw.Write([]byte(fmt.Sprintf("%v\t%v\n", k, countMap[k]))); err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
