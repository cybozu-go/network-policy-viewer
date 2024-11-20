package app

import (
	"context"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	rootCmd.AddCommand(summaryCmd)
}

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show summary of network policy count",
	Long:  `Show summary of network policy count`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSummary(context.Background(), cmd.OutOrStdout())
	},
}

type summaryEntry struct {
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	IngressAllow int    `json:"ingress_allow"`
	IngressDeny  int    `json:"ingress_deny"`
	EgressAllow  int    `json:"egress_allow"`
	EgressDeny   int    `json:"egress_deny"`
}

func lessSummaryEntry(x, y *summaryEntry) bool {
	ret := strings.Compare(x.Namespace, y.Namespace)
	if ret == 0 {
		ret = strings.Compare(x.Name, y.Name)
	}
	return ret < 0
}

func runSummary(ctx context.Context, w io.Writer) error {
	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	summary := make([]summaryEntry, 0)
	pods, err := clientset.CoreV1().Pods(rootOptions.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, p := range pods.Items {
		var entry summaryEntry
		entry.Namespace = p.Namespace
		entry.Name = p.Name

		// Skip non-relevant pods
		if p.Spec.HostNetwork {
			continue
		}
		if p.Status.Phase != corev1.PodRunning {
			continue
		}

		policies, err := queryPolicyMap(ctx, clientset, dynamicClient, rootOptions.namespace, p.Name)
		if err != nil {
			return err
		}

		for _, p := range policies {
			switch {
			case p.IsEgressRule() && p.IsDenyRule():
				entry.EgressDeny++
			case p.IsEgressRule() && !p.IsDenyRule():
				entry.EgressAllow++
			case !p.IsEgressRule() && p.IsDenyRule():
				entry.IngressDeny++
			case !p.IsEgressRule() && !p.IsDenyRule():
				entry.IngressAllow++
			}
		}
		summary = append(summary, entry)
	}
	sort.Slice(summary, func(i, j int) bool { return lessSummaryEntry(&summary[i], &summary[j]) })

	header := []string{"NAMESPACE", "NAME", "INGRESS-ALLOW", "INGRESS-DENY", "EGRESS-ALLOW", "EGRESS-DENY"}
	return writeSimpleOrJson(w, summary, header, len(summary), func(index int) []any {
		p := summary[index]
		return []any{p.Namespace, p.Name, p.IngressAllow, p.IngressDeny, p.EgressAllow, p.EgressDeny}
	})
}
