package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	idCmd.AddCommand(idTreeCmd)
}

var idTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Display CiliumIdentity hierarchy",
	Long:  `Display CiliumIdentity hierarchy`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runIdTree(context.Background(), cmd.OutOrStdout())
	},
}

type idTreeEntry struct {
	identity uint32
	labels   map[string]string
}

func runIdTree(ctx context.Context, w io.Writer) error {
	_, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	li, err := dynamicClient.Resource(gvrIdentity).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	items := make([]idTreeEntry, 0)
	for _, item := range li.Items {
		var e idTreeEntry
		id, err := strconv.Atoi(item.GetName())
		if err != nil {
			return err
		}
		e.identity = uint32(id)

		labels, ok, err := unstructured.NestedStringMap(item.Object, "security-labels")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if ns, ok := labels["k8s:io.kubernetes.pod.namespace"]; ok {
			if !(rootOptions.allNamespaces || ns == rootOptions.namespace) {
				continue
			}
		}
		e.labels = labels
		items = append(items, e)
	}

	idEndpoints, err := getIdentityEndpoints(ctx, dynamicClient)
	if err != nil {
		return err
	}

	return walkIdTree(w, items, idEndpoints, "")
}

func computeLabelMap(entries []idTreeEntry) map[string][]string {
	var keys []string
	{
		keyMap := make(map[string]any)
		for _, e := range entries {
			for k := range e.labels {
				keyMap[k] = struct{}{}
			}
		}
		keys = slices.Collect(maps.Keys(keyMap))
	}

	ret := make(map[string][]string)
	for _, k := range keys {
		values := make(map[string]any)
		for _, e := range entries {
			values[e.labels[k]] = struct{}{}
		}
		ret[k] = slices.Collect(maps.Keys(values))
		slices.Sort(ret[k])
	}
	return ret
}

func findPrimaryKey(labelMap map[string][]string) (key string, cardinality int) {
	special := []string{
		"k8s:io.cilium.k8s.policy.cluster",
		"k8s:io.kubernetes.pod.namespace",
	}
	for _, k := range special {
		if v, ok := labelMap[k]; ok {
			key = k
			cardinality = len(v)
			return
		}
	}

	keys := slices.Collect(maps.Keys(labelMap))
	slices.Sort(keys)

	key = ""
	cardinality = math.MaxInt32
	for _, k := range keys {
		v := labelMap[k]
		if len(v) < cardinality {
			key = k
			cardinality = len(v)
		}
	}
	return key, cardinality
}

// ref. https://github.com/cybozu-go/accurate/blob/main/cmd/kubectl-accurate/sub/list.go
func walkIdTree(w io.Writer, entries []idTreeEntry, idEndpoints map[uint32][]*unstructured.Unstructured, prefix string) error {
	const (
		KeyColor   = 0
		ValueColor = 32
		PodColor   = 90
	)
	cleanup := func(li []idTreeEntry, key string) {
		for _, e := range li {
			delete(e.labels, key)
		}
	}

	labelMap := computeLabelMap(entries)
	if len(labelMap) == 0 {
		eps := make([]string, 0)
		for _, entry := range entries {
			for _, ep := range idEndpoints[entry.identity] {
				eps = append(eps, ep.GetName())
			}
		}
		slices.Sort(eps)
		for i, ep := range eps {
			isLast := i == len(eps)-1
			if !isLast {
				fmt.Println(prefix + "├── " + colored(PodColor, "[Pod] ") + ep)
			} else {
				fmt.Println(prefix + "└── " + colored(PodColor, "[Pod] ") + ep)
			}
		}
		return nil
	}

	key, cardinality := findPrimaryKey(labelMap)

	switch cardinality {
	case 1:
		fmt.Println(prefix + colored(KeyColor, key) + ": " + colored(ValueColor, labelMap[key][0]))
		cleanup(entries, key)
		walkIdTree(w, entries, idEndpoints, prefix)
	default:
		fmt.Println(prefix + colored(KeyColor, key))
		values := labelMap[key]

		for i, v := range values {
			children := make([]idTreeEntry, 0)
			for _, e := range entries {
				if e.labels[key] == v {
					children = append(children, e)
				}
			}
			if v == "" {
				v = "(null)"
			}

			isLast := i == len(values)-1
			if !isLast {
				fmt.Println(prefix + "├── " + colored(ValueColor, v))
				cleanup(children, key)
				walkIdTree(w, children, idEndpoints, prefix+"│   ")
			} else {
				fmt.Println(prefix + "└── " + colored(ValueColor, v))
				cleanup(children, key)
				walkIdTree(w, children, idEndpoints, prefix+"    ")
			}
		}
	}
	return nil
}
