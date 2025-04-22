package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

var cachedCiliumClients map[string]*client.Client

func init() {
	cachedCiliumClients = make(map[string]*client.Client)
}

func createK8sClients() (*kubernetes.Clientset, *dynamic.DynamicClient, error) {
	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}

	return clientset, dynamicClient, nil
}

func getPodEndpointID(ctx context.Context, d *dynamic.DynamicClient, namespace, name string) (int64, error) {
	ep, err := d.Resource(gvrEndpoint).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}

	endpointID, found, err := unstructured.NestedInt64(ep.Object, "status", "id")
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("endpoint resource %s/%s is broken", namespace, name)
	}

	return endpointID, nil
}

func getPodIdentity(ctx context.Context, d *dynamic.DynamicClient, namespace, name string) (int64, error) {
	ep, err := d.Resource(gvrEndpoint).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}

	identity, found, err := unstructured.NestedInt64(ep.Object, "status", "identity", "id")
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("pod %s/%s does not have security identity", namespace, name)
	}

	return identity, nil
}

func listRelevantPods(ctx context.Context, c *kubernetes.Clientset, namespace string, opts metav1.ListOptions) ([]corev1.Pod, error) {
	pods, err := c.CoreV1().Pods(namespace).List(ctx, opts)
	if err != nil {
		return nil, err
	}

	ret := make([]corev1.Pod, 0)
	for _, p := range pods.Items {
		// Skip non-relevant pods
		if p.Spec.HostNetwork {
			continue
		}
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		ret = append(ret, p)
	}
	return ret, nil
}

// key: identity number
// value: CiliumIdentity resource
func getIdentityResourceMap(ctx context.Context, d *dynamic.DynamicClient) (map[int]*unstructured.Unstructured, error) {
	li, err := d.Resource(gvrIdentity).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	ret := make(map[int]*unstructured.Unstructured)
	for _, item := range li.Items {
		id, err := strconv.Atoi(item.GetName())
		if err != nil {
			return nil, err
		}
		ret[id] = &item
	}
	return ret, nil
}

// key: identity number
// value: CiliumEndpoint array
func getIdentityEndpoints(ctx context.Context, d *dynamic.DynamicClient) (map[int][]*unstructured.Unstructured, error) {
	li, err := d.Resource(gvrEndpoint).Namespace(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	ret := make(map[int][]*unstructured.Unstructured)
	for _, ep := range li.Items {
		identity64, ok, err := unstructured.NestedInt64(ep.Object, "status", "identity", "id")
		identity := int(identity64)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		ret[identity] = append(ret[identity], &ep)
	}
	return ret, nil
}

func parseNamespacedName(nn string) (types.NamespacedName, error) {
	li := strings.Split(nn, "/")
	if len(li) != 2 {
		return types.NamespacedName{}, errors.New("input is not NAMESPACE/NAME")
	}
	return types.NamespacedName{Namespace: li[0], Name: li[1]}, nil
}

func writeSimpleOrJson(w io.Writer, content any, header []string, count int, values func(index int) []any) error {
	switch rootOptions.output {
	case OutputJson:
		text, err := json.MarshalIndent(content, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(text)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{'\n'})
		return err
	case OutputSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		if !rootOptions.noHeaders {
			if _, err := tw.Write([]byte(strings.Join(header, "\t") + "\n")); err != nil {
				return err
			}
		}
		for i := range count {
			format := strings.Repeat("%v\t", len(header)-1) + "%v\n"
			if _, err := tw.Write([]byte(fmt.Sprintf(format, values(i)...))); err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
