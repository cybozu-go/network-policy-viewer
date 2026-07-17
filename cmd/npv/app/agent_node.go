package app

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
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
	c, err := k8s.NewClient()
	if err != nil {
		return err
	}

	var n corev1.Node
	if err := c.Get(ctx, types.NamespacedName{Name: node}, &n); err != nil {
		return fmt.Errorf("failed to get node %s: %w", node, err)
	}

	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace("kube-system"),
		client.MatchingFields{"spec.nodeName": node},
		client.MatchingLabels{"k8s-app": "cilium"}); err != nil {
		return err
	}
	if num := len(pods.Items); num != 1 {
		return fmt.Errorf("failed to find cilium-agent. found %d pods", num)
	}

	_, err = fmt.Fprintln(w, pods.Items[0].Name)
	return err
}
