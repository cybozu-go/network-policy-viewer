package app

import (
	"context"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

func completeNamespaces(cmd *cobra.Command, args []string, toComplete string) (ret []string, directive cobra.ShellCompDirective) {
	ret = make([]string, 0)
	directive = cobra.ShellCompDirectiveNoFileComp
	if err := fillOptions(cmd); err != nil {
		return
	}

	c, err := k8s.NewClient()
	if err != nil {
		return
	}

	var nss corev1.NamespaceList
	if err := c.List(context.Background(), &nss); err != nil {
		return
	}

	for _, ns := range nss.Items {
		ret = append(ret, ns.Name)
	}
	return
}

func completeNodes(cmd *cobra.Command, args []string, toComplete string) (ret []string, directive cobra.ShellCompDirective) {
	ret = make([]string, 0)
	directive = cobra.ShellCompDirectiveNoFileComp
	if err := fillOptions(cmd); err != nil {
		return
	}

	c, err := k8s.NewClient()
	if err != nil {
		return
	}

	var nodes corev1.NodeList
	if err := c.List(context.Background(), &nodes); err != nil {
		return
	}

	for _, node := range nodes.Items {
		ret = append(ret, node.Name)
	}
	return
}

func completePods(cmd *cobra.Command, args []string, toComplete string) (ret []string, directive cobra.ShellCompDirective) {
	ret = make([]string, 0)
	directive = cobra.ShellCompDirectiveNoFileComp
	if err := fillOptions(cmd); err != nil {
		return
	}

	c, err := k8s.NewClient()
	if err != nil {
		return
	}

	nsOptions, err := subject.GetNamespaceListOptions()
	if err != nil {
		return
	}

	podOptions, err := subject.GetPodListOptions()
	if err != nil {
		return
	}

	pods, err := subject.ListCiliumManagedPods(context.Background(), c, nsOptions, podOptions)
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
	if err := fillOptions(cmd); err != nil {
		return
	}

	c, err := k8s.NewClient()
	if err != nil {
		return
	}

	li := strings.Split(toComplete, "/")
	switch len(li) {
	case 2: // namespace already filled
		nsOptions := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", li[0]),
		}
		podOptions, err := subject.GetPodListOptions()
		if err != nil {
			return
		}

		pods, err := subject.ListCiliumManagedPods(context.Background(), c, nsOptions, podOptions)
		if err != nil {
			return
		}
		for _, p := range pods {
			ret = append(ret, li[0]+"/"+p.Name)
		}
		return

	default:
		nsOptions, err := subject.GetNamespaceListOptions()
		if err != nil {
			return
		}

		var nss corev1.NamespaceList
		if err := c.List(context.Background(), &nss, nsOptions); err != nil {
			return
		}

		for _, ns := range nss.Items {
			ret = append(ret, ns.Name+"/")
		}
		directive = cobra.ShellCompDirectiveNoSpace
		return
	}
}
