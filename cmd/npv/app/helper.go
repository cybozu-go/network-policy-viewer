package app

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	directionEgress  = "Egress"
	directionIngress = "Ingress"

	policyAllow = "Allow"
	policyDeny  = "Deny"
)

var cachedCiliumClients map[string]*client.Client

var gvrEndpoint schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumendpoints",
}

var gvrIdentity schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumidentities",
}

func init() {
	cachedCiliumClients = make(map[string]*client.Client)
}

func createK8sClients() (*kubernetes.Clientset, *dynamic.DynamicClient, error) {
	config, err := rest.InClusterConfig()
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

func createCiliumClient(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string) (*client.Client, error) {
	endpoint, err := getProxyEndpoint(ctx, clientset, namespace, name)
	if err != nil {
		return nil, err
	}

	if cached, ok := cachedCiliumClients[endpoint]; ok {
		return cached, nil
	}

	ciliumClient, err := client.NewClient(endpoint)
	if err != nil {
		return nil, err
	}
	cachedCiliumClients[endpoint] = ciliumClient

	return ciliumClient, err
}

func getProxyEndpoint(ctx context.Context, c *kubernetes.Clientset, namespace, name string) (string, error) {
	targetPod, err := c.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	targetNode := targetPod.Spec.NodeName

	pods, err := c.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + targetNode,
		LabelSelector: rootOptions.proxySelector,
	})
	if err != nil {
		return "", err
	}
	if num := len(pods.Items); num != 1 {
		err := fmt.Errorf("failed to find cilium-agent-proxy. found %d pods", num)
		return "", err
	}

	podIP := pods.Items[0].Status.PodIP
	return fmt.Sprintf("http://%s:%d", podIP, rootOptions.proxyPort), nil
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
		return 0, errors.New("endpoint resource is broken")
	}

	return endpointID, nil
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
// value: example pod name
func getIdentityExampleMap(ctx context.Context, d *dynamic.DynamicClient) (map[int]string, error) {
	li, err := d.Resource(gvrEndpoint).Namespace(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	ret := make(map[int]string)
	for _, ep := range li.Items {
		identity, ok, err := unstructured.NestedInt64(ep.Object, "status", "identity", "id")
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if _, ok := ret[int(identity)]; ok {
			ret[int(identity)] += "," + ep.GetName()
		} else {
			ret[int(identity)] = ep.GetName()
		}
	}
	for k, v := range ret {
		if strings.Contains(v, ",") {
			samples := strings.Split(v, ",")
			i := rand.Intn(len(samples))
			ret[k] = samples[i]
		}
	}
	return ret, nil
}
