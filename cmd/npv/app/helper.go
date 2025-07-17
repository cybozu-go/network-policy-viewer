package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

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
		return listCiliumManagedPods(ctx, clientset, ns, metav1.ListOptions{
			LabelSelector: selector,
		})
	}
}

func listCiliumManagedPods(ctx context.Context, c *kubernetes.Clientset, namespace string, opts metav1.ListOptions) ([]*corev1.Pod, error) {
	node := rootOptions.node
	if node != "" {
		baseSelector, err := fields.ParseSelector(opts.FieldSelector)
		if err != nil {
			return nil, err
		}
		nodeSelector := fields.OneTermEqualSelector("spec.nodeName", rootOptions.node)
		opts.FieldSelector = fields.AndSelectors(baseSelector, nodeSelector).String()
	}

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

func parseCIDRFlag(expr string) (incl []*net.IPNet, excl []*net.IPNet, err error) {
	incl = make([]*net.IPNet, 0)
	excl = make([]*net.IPNet, 0)
	if expr == "" {
		return
	}

	fields := strings.Split(expr, ",")
	for _, f := range fields {
		not := false
		if f[0] == '!' {
			not = true
			f = f[1:]
		}

		var cidr *net.IPNet
		if _, cidr, err = net.ParseCIDR(f); err != nil {
			return
		}
		if not {
			excl = append(excl, cidr)
		} else {
			incl = append(incl, cidr)
		}
	}

	if len(incl) == 0 {
		err = errors.New("at least one inclusive CIDR rule should be specified")
	}
	return
}

func isChildCIDR(parent, child *net.IPNet) bool {
	if parent == nil || child == nil {
		return false
	}
	if !parent.Contains(child.IP) {
		return false
	}
	p, _ := parent.Mask.Size()
	c, _ := child.Mask.Size()
	return p <= c
}

func formatWithUnits(v int) string {
	if v < 1024 || !rootOptions.units {
		return strconv.Itoa(v)
	}

	units := "_KMGTPEZY"
	i := 0
	fv := float64(v)
	for fv >= 1024 {
		i += 1
		fv /= 1024
	}
	return fmt.Sprintf("%.1f%c", fv, units[i])
}

func computeAverage(bytes, count int) float64 {
	if count == 0 {
		return 0
	}
	return float64(bytes) / float64(count)
}

func writeSimpleOrJson(w io.Writer, content any, header []string, count int, values func(index int) []any) error {
	expr := make([][]any, 0)
	for i := range count {
		expr = append(expr, values(i))
	}

	if rootOptions.output == OutputSimple {
		header = slices.Clone(header)
		for j := 0; j < len(header); j++ {
			h := header[j]
			if strings.HasSuffix(h, ":") {
				h = h[:len(h)-1]
				header[j] = h
				width := len(h)
				for i := 0; i < count; i++ {
					v := fmt.Sprintf("%v", expr[i][j])
					width = max(width, len(v))
					expr[i][j] = v
				}

				format := fmt.Sprintf("%%%ds", width)
				header[j] = fmt.Sprintf(format, header[j])
				for i := 0; i < count; i++ {
					expr[i][j] = fmt.Sprintf(format, expr[i][j])
				}
			}
		}
	}

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
			if _, err := tw.Write([]byte(fmt.Sprintf(format, expr[i]...))); err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
