package subject

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	GroupAll       = "all"
	GroupNamespace = "namespace"
	GroupPod       = "pod"
)

type SelectorConfig struct {
	AllNamespaces bool
	Namespace     string
	PodSelector   string
	Node          string
}

var (
	group          string
	selectorConfig *SelectorConfig
)

func init() {
	group = GroupPod
}

func GetGroup() string {
	return group
}

func SetGroup(g string) error {
	switch g {
	case "a", "all":
		g = GroupAll
	case "n", "ns", "namespace", "namespaces":
		g = GroupNamespace
	case "p", "po", "pod", "pods", "":
		g = GroupPod
	default:
		return fmt.Errorf("failed to parse --group: should be one of: all [a], ns [n], pod [p]")
	}
	group = g
	return nil
}

func GetSelectorConfig() *SelectorConfig {
	return selectorConfig
}

func SetSelectorConfig(c *SelectorConfig) {
	selectorConfig = c
}

func ListCiliumManagedPods(ctx context.Context, c *kubernetes.Clientset, namespace string, opts metav1.ListOptions) ([]*corev1.Pod, error) {
	pods, err := c.CoreV1().Pods(namespace).List(ctx, opts)
	if err != nil {
		return nil, err
	}

	ret := make([]*corev1.Pod, 0)
	for _, p := range pods.Items {
		// Skip non-relevant pods
		if p.Spec.HostNetwork {
			continue
		}
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		ret = append(ret, &p)
	}
	return ret, nil
}
