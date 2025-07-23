package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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
		return runSummary(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr())
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

func runSummaryOnPod(ctx context.Context, clientset *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, pod *corev1.Pod) (summaryEntry, error) {
	var entry summaryEntry
	entry.Namespace = pod.Namespace
	entry.Name = pod.Name

	policies, err := queryPolicyMap(ctx, clientset, dynamicClient, pod.Namespace, pod.Name)
	if err != nil {
		return entry, err
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
	return entry, nil
}

func runSummary(ctx context.Context, stdout, stderr io.Writer) error {
	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	summary := make([]summaryEntry, 0)
	pods, err := listCiliumManagedPods(ctx, clientset, getSubjectNamespace(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, p := range pods {
		entry, err := runSummaryOnPod(ctx, clientset, dynamicClient, p)
		if err != nil {
			fmt.Fprintf(stderr, "* %v\n", err)
			continue
		}
		summary = append(summary, entry)
	}
	sort.Slice(summary, func(i, j int) bool { return lessSummaryEntry(&summary[i], &summary[j]) })

	header := []string{"NAMESPACE", "NAME", "INGRESS-ALLOW", "INGRESS-DENY", "EGRESS-ALLOW", "EGRESS-DENY"}
	return writeSimpleOrJson(stdout, summary, header, len(summary), func(index int) []any {
		p := summary[index]
		return []any{p.Namespace, p.Name, p.IngressAllow, p.IngressDeny, p.EgressAllow, p.EgressDeny}
	})
}
