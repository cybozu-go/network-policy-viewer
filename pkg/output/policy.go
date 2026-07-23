package output

import (
	"fmt"
	"io"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"go.yaml.in/yaml/v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cybozu-go/network-policy-viewer/pkg/gvk"
)

func cleanFields(obj map[string]any) {
	unstructured.RemoveNestedField(obj, "metadata", "annotations", "kubectl.kubernetes.io/last-applied-configuration")
	unstructured.RemoveNestedField(obj, "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(obj, "metadata", "generation")
	unstructured.RemoveNestedField(obj, "metadata", "managedFields")
	unstructured.RemoveNestedField(obj, "metadata", "resourceVersion")
	unstructured.RemoveNestedField(obj, "metadata", "uid")
	unstructured.RemoveNestedField(obj, "status")
}

func WriteManifests(w io.Writer, ccnps []*ciliumv2.CiliumClusterwideNetworkPolicy, cnps []*ciliumv2.CiliumNetworkPolicy) error {
	first := true
	for _, ccnp := range ccnps {
		if !first {
			fmt.Fprintln(w, "---")
		}
		first = false

		ccnp = ccnp.DeepCopy()
		ccnp.SetGroupVersionKind(gvk.ClusterwideNetworkPolicy)
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&ccnp)
		if err != nil {
			return err
		}
		cleanFields(obj)

		data, err := yaml.Marshal(obj)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s", string(data))
	}

	for _, cnp := range cnps {
		if !first {
			fmt.Fprintln(w, "---")
		}
		first = false

		cnp = cnp.DeepCopy()
		cnp.SetGroupVersionKind(gvk.NetworkPolicy)
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&cnp)
		if err != nil {
			return err
		}
		cleanFields(obj)

		data, err := yaml.Marshal(obj)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s", string(data))
	}
	return nil
}
