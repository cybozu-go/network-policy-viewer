package subject

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

const (
	GroupAll       = "all"
	GroupNamespace = "namespace"
	GroupPod       = "pod"
)

type SelectorConfig struct {
	AllNamespaces     bool
	NamespaceSelector string
	Namespace         string
	PodSelector       string
	Node              string
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

func GetNamespaceListOptions() metav1.ListOptions {
	switch {
	case selectorConfig.AllNamespaces:
		return metav1.ListOptions{}
	case selectorConfig.NamespaceSelector != "":
		return metav1.ListOptions{
			LabelSelector: selectorConfig.NamespaceSelector,
		}
	case selectorConfig.Namespace != "":
		return metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", selectorConfig.Namespace).String(),
		}
	default:
		return metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", "default").String(),
		}
	}
}

func GetPodListOptions() metav1.ListOptions {
	opts := metav1.ListOptions{
		LabelSelector: selectorConfig.PodSelector,
	}
	if selectorConfig.Node != "" {
		opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", selectorConfig.Node).String()
	}
	return opts
}

// ShouldPrintSubject reports whether the result table should include a subject row.
func ShouldPrintSubject(podName string) bool {
	switch group {
	case GroupAll:
		return false
	case GroupNamespace:
		return selectorConfig.AllNamespaces
	case GroupPod:
		return podName == ""
	default:
		panic("internal error")
	}
}

func GetPodSubject(namespace, name string) string {
	switch group {
	case GroupAll:
		return ""
	case GroupNamespace:
		return namespace
	case GroupPod:
		if selectorConfig.AllNamespaces || selectorConfig.NamespaceSelector != "" {
			return namespace + "/" + name
		} else {
			return name
		}
	default:
		panic("internal error")
	}
}

// ListSubjectPods returns the pods that should be examined according to the current options.
func ListSubjectPods(ctx context.Context, clientset *kubernetes.Clientset, name string) ([]*corev1.Pod, error) {
	if (name != "") && (selectorConfig.AllNamespaces || selectorConfig.NamespaceSelector != "" || selectorConfig.PodSelector != "") {
		return nil, errors.New("multiple pods should not be selected when pod name is specified")
	}

	if name != "" {
		pod, err := clientset.CoreV1().Pods(selectorConfig.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return []*corev1.Pod{pod}, nil
	} else {
		return ListCiliumManagedPods(ctx, clientset, GetNamespaceListOptions(), GetPodListOptions())
	}
}

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
