package subject

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func IsMultiNamespace() bool {
	return selectorConfig.AllNamespaces || selectorConfig.NamespaceSelector != ""
}

func GetNamespaceListOptions() (*client.ListOptions, error) {
	switch {
	case selectorConfig.AllNamespaces:
		return &client.ListOptions{}, nil
	case selectorConfig.NamespaceSelector != "":
		selector, err := labels.Parse(selectorConfig.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		return &client.ListOptions{
			LabelSelector: selector,
		}, nil
	case selectorConfig.Namespace != "":
		return &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", selectorConfig.Namespace),
		}, nil
	default:
		return &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", "default"),
		}, nil
	}
}

func GetPodListOptions() (*client.ListOptions, error) {
	selector, err := labels.Parse(selectorConfig.PodSelector)
	if err != nil {
		return nil, err
	}

	opts := client.ListOptions{
		LabelSelector: selector,
	}
	if selectorConfig.Node != "" {
		opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", selectorConfig.Node)
	}
	return &opts, nil
}

// ShouldPrintSubject reports whether the result table should include a subject row.
func ShouldPrintSubject(podName string) bool {
	switch group {
	case GroupAll:
		return false
	case GroupNamespace:
		return IsMultiNamespace()
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
		if IsMultiNamespace() {
			return namespace + "/" + name
		} else {
			return name
		}
	default:
		panic("internal error")
	}
}

// ListSubjectPods returns the pods that should be examined according to the current options.
func ListSubjectPods(ctx context.Context, c client.Client, name string) ([]*corev1.Pod, error) {
	if (name != "") && (IsMultiNamespace() || selectorConfig.PodSelector != "") {
		return nil, errors.New("multiple pods should not be selected when pod name is specified")
	}

	if name != "" {
		var pod corev1.Pod
		if err := c.Get(ctx, types.NamespacedName{Namespace: selectorConfig.Namespace, Name: name}, &pod); err != nil {
			return nil, err
		}
		return []*corev1.Pod{&pod}, nil
	} else {
		nsOptions, err := GetNamespaceListOptions()
		if err != nil {
			return nil, err
		}

		podOptions, err := GetPodListOptions()
		if err != nil {
			return nil, err
		}
		return ListCiliumManagedPods(ctx, c, nsOptions, podOptions)
	}
}

func ListCiliumManagedPods(ctx context.Context, c client.Client, nsOptions *client.ListOptions, podOptions *client.ListOptions) ([]*corev1.Pod, error) {
	var nss corev1.NamespaceList
	if err := c.List(ctx, &nss, nsOptions); err != nil {
		return nil, err
	}

	ret := make([]*corev1.Pod, 0)
	for _, n := range nss.Items {
		opts := *podOptions
		opts.Namespace = n.Name

		var pods corev1.PodList
		if err := c.List(ctx, &pods, &opts); err != nil {
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
