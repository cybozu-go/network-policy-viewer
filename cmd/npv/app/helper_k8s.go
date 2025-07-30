package app

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	cachedIdentities        map[int]*unstructured.Unstructured
	cachedIdentityEndpoints map[int][]*unstructured.Unstructured
	cachedIdentityExample   = make(map[int]*unstructured.Unstructured)
)

func parseNamespacedName(nn string) (types.NamespacedName, error) {
	li := strings.Split(nn, "/")
	if len(li) != 2 {
		return types.NamespacedName{}, errors.New("input is not NAMESPACE/NAME")
	}
	return types.NamespacedName{Namespace: li[0], Name: li[1]}, nil
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

func getSubjectNamespace() string {
	if rootOptions.allNamespaces {
		return ""
	}
	return rootOptions.namespace
}

func selectSubjectPods(ctx context.Context, clientset *kubernetes.Clientset, name, selector string) ([]*corev1.Pod, error) {
	if (name != "") && (rootOptions.allNamespaces || selector != "") {
		return nil, errors.New("multiple pods should not be selected when pod name is specified")
	}

	ns := getSubjectNamespace()
	if name != "" {
		pod, err := clientset.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return []*corev1.Pod{pod}, nil
	} else {
		opts := metav1.ListOptions{
			LabelSelector: selector,
		}
		node := rootOptions.node
		if node != "" {
			opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", rootOptions.node).String()
		}

		return listCiliumManagedPods(ctx, clientset, ns, opts)
	}
}

func listCiliumManagedPods(ctx context.Context, c *kubernetes.Clientset, namespace string, opts metav1.ListOptions) ([]*corev1.Pod, error) {
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

// key: identity number
// value: CiliumIdentity resource
func getIdentityResourceMap(ctx context.Context, d *dynamic.DynamicClient) (map[int]*unstructured.Unstructured, error) {
	if cachedIdentities != nil {
		return cachedIdentities, nil
	}

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
	cachedIdentities = ret
	return ret, nil
}

// key: identity number
// value: CiliumEndpoint array
func getIdentityEndpoints(ctx context.Context, d *dynamic.DynamicClient) (map[int][]*unstructured.Unstructured, error) {
	if cachedIdentityEndpoints != nil {
		return cachedIdentityEndpoints, nil
	}

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
	cachedIdentityEndpoints = ret
	return ret, nil
}

// getIdentityExample returns a consistent example endpoint for a CiliumIdentity within process' lifetime.
// key: identity number
// value: CiliumEndpoint
func getIdentityExample(ctx context.Context, d *dynamic.DynamicClient, id int) (*unstructured.Unstructured, error) {
	if cached, ok := cachedIdentityExample[id]; ok {
		return cached, nil
	}

	idEndpoints, err := getIdentityEndpoints(ctx, d)
	if err != nil {
		return nil, err
	}

	eps, ok := idEndpoints[id]
	if !ok || len(eps) == 0 {
		cachedIdentityExample[id] = nil
		return nil, nil
	}

	i := rand.IntN(len(eps))
	ret := eps[i]
	cachedIdentityExample[id] = ret
	return ret, nil
}
