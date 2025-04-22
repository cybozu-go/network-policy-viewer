package app

import (
	"context"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func completeNamespaces(cmd *cobra.Command, args []string, toComplete string) (ret []string, directive cobra.ShellCompDirective) {
	ret = make([]string, 0)
	directive = cobra.ShellCompDirectiveNoFileComp

	clientset, _, err := createK8sClients()
	if err != nil {
		return
	}

	nss, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, ns := range nss.Items {
		ret = append(ret, ns.Name)
	}
	return
}

func completePods(cmd *cobra.Command, args []string, toComplete string) (ret []string, directive cobra.ShellCompDirective) {
	ret = make([]string, 0)
	directive = cobra.ShellCompDirectiveNoFileComp

	clientset, _, err := createK8sClients()
	if err != nil {
		return
	}

	pods, err := listRelevantPods(context.Background(), clientset, rootOptions.namespace, metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, p := range pods {
		ret = append(ret, p.Name)
	}
	return
}

func completeNamespacePods(cmd *cobra.Command, args []string, toComplete string) (ret []string, directive cobra.ShellCompDirective) {
	ret = make([]string, 0)
	directive = cobra.ShellCompDirectiveNoFileComp

	clientset, _, err := createK8sClients()
	if err != nil {
		return
	}

	li := strings.Split(toComplete, "/")
	switch len(li) {
	case 2: // namespace already filled
		pods, err := listRelevantPods(context.Background(), clientset, li[0], metav1.ListOptions{})
		if err != nil {
			return
		}
		for _, p := range pods {
			ret = append(ret, li[0]+"/"+p.Name)
		}
		return

	default:
		nss, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return
		}

		for _, ns := range nss.Items {
			ret = append(ret, ns.Name+"/")
		}
		directive = cobra.ShellCompDirectiveNoSpace
		return
	}
}
