package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var dumpOptions struct {
	namespace string
}

func init() {
	dumpCmd.Flags().StringVarP(&dumpOptions.namespace, "namespace", "n", "", "namespace of a pod")
	rootCmd.AddCommand(dumpCmd)
}

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dump endpoint status",
	Long:  `Dump endpoint status`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDump(context.Background(), args[0])
	},
}

func runDump(ctx context.Context, name string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, _ := kubernetes.NewForConfig(config)
	pod, err := clientset.CoreV1().Pods(dumpOptions.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	node := pod.Spec.NodeName
	proxy, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
		LabelSelector: "app.kubernetes.io/name=cilium-agent-proxy",
	})
	if err != nil {
		return err
	}
	if len(proxy.Items) != 1 {
		return errors.New("proxy not found")
	}
	proxyIP := proxy.Items[0].Status.PodIP

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}

	gvr := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumendpoints",
	}
	obj, err := client.Resource(gvr).Namespace(dumpOptions.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	endpointID, found, err := unstructured.NestedInt64(obj.Object, "status", "id")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("endpoint not found")
	}

	url := fmt.Sprintf("http://%s:8080/v1/endpoint/%d", proxyIP, endpointID)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
