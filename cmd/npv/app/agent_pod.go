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
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

func init() {
	addNamespaceOption(agentPodCmd)
	agentCmd.AddCommand(agentPodCmd)
}

var agentPodCmd = &cobra.Command{
	Use:   "pod",
	Short: "Show cilium-agent for a pod",
	Long:  `Show cilium-agent for a pod`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAgentPod(context.Background(), cmd.OutOrStdout(), args[0])
	},
	ValidArgsFunction: completePods,
}

func runAgentPod(ctx context.Context, w io.Writer, name string) error {
	c, err := k8s.NewClient()
	if err != nil {
		return err
	}

	selector := subject.GetSelectorConfig()

	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Namespace: selector.Namespace, Name: name}, &pod); err != nil {
		return err
	}

	var pods corev1.PodList
	if err := c.List(ctx, &pods,
		client.InNamespace("kube-system"),
		client.MatchingFields{"spec.nodeName": pod.Spec.NodeName},
		client.MatchingLabels{"k8s-app": "cilium"},
	); err != nil {
		return err
	}
	if num := len(pods.Items); num != 1 {
		return fmt.Errorf("failed to find cilium-agent. found %d pods", num)
	}

	_, err = fmt.Fprintln(w, pods.Items[0].Name)
	return err
}
