package app

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	agentCmd.AddCommand(agentNodeCmd)
}

var agentNodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Show cilium-agent for a node",
	Long:  `Show cilium-agent for a node`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAgentNode(context.Background(), cmd.OutOrStdout(), args[0])
	},
	ValidArgsFunction: completeNodes,
}

func runAgentNode(ctx context.Context, w io.Writer, node string) error {
	clientset, _, err := createK8sClients()
	if err != nil {
		return err
	}

	if _, err = clientset.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{}); err != nil {
		return fmt.Errorf("failed to get node %s: %w", node, err)
	}

	pods, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
		LabelSelector: "k8s-app=cilium",
	})
	if err != nil {
		return err
	}
	if num := len(pods.Items); num != 1 {
		return fmt.Errorf("failed to find cilium-agent. found %d pods", num)
	}

	fmt.Fprintln(w, pods.Items[0].Name)
	return nil
}
