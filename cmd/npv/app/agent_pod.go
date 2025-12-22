package app

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
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
	clientset, _, err := createK8sClients()
	if err != nil {
		return err
	}

	pod, err := clientset.CoreV1().Pods(rootOptions.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	pods, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + pod.Spec.NodeName,
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
