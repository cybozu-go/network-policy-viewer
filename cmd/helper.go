package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func createClients(ctx context.Context, name string) (*kubernetes.Clientset, *dynamic.DynamicClient, *client.Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, nil, err
	}

	// Create Kubernetes Clients
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, nil, err
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create Cilium Client
	endpoint, err := getProxyEndpoint(ctx, clientset, rootOptions.namespace, name)
	if err != nil {
		return nil, nil, nil, err
	}
	ciliumClient, err := client.NewClient(endpoint)
	if err != nil {
		return nil, nil, nil, err
	}

	return clientset, dynamicClient, ciliumClient, err
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
	gvr := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumendpoints",
	}

	ep, err := d.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
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
