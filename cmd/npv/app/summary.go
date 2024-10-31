package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
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

		if p.Spec.HostNetwork {
			entry.EgressDeny = -1
			entry.EgressAllow = -1
			entry.IngressDeny = -1
			entry.IngressAllow = -1
		} else {
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
		}
		summary = append(summary, entry)
	}
	sort.Slice(summary, func(i, j int) bool { return lessSummaryEntry(&summary[i], &summary[j]) })

	switch rootOptions.output {
	case OutputJson:
		text, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(text)
		return err
	case OutputSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		if !rootOptions.noHeaders {
			if _, err := tw.Write([]byte("NAMESPACE\tNAME\tINGRESS-ALLOW\tINGRESS-DENY\tEGRESS-ALLOW\tEGRESS-DENY\n")); err != nil {
				return err
			}
		}
		for _, p := range summary {
			if _, err := tw.Write([]byte(fmt.Sprintf("%v\t%v\t%v\t%v\t%v\t%v\n", p.Namespace, p.Name, p.IngressAllow, p.IngressDeny, p.EgressAllow, p.EgressDeny))); err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
