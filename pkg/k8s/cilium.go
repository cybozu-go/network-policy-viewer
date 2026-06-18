package k8s

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func ListCiliumManagedPods(ctx context.Context, c *kubernetes.Clientset, nsOptions metav1.ListOptions, podOptions metav1.ListOptions) ([]*corev1.Pod, error) {
	nss, err := c.CoreV1().Namespaces().List(ctx, nsOptions)
	if err != nil {
		return nil, err
	}

	ret := make([]*corev1.Pod, 0)
	for _, n := range nss.Items {
		pods, err := c.CoreV1().Pods(n.Name).List(ctx, podOptions)
		if err != nil {
			return nil, err
		}

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
	}
	return ret, nil
}
