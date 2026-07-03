package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

func init() {
	addPodSelectorOption(idTreeCmd)
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
	c, err := k8s.NewClient()
	if err != nil {
		return err
	}

	var nss corev1.NamespaceList
	if err := c.List(ctx, &nss, subject.GetClientNamespaceListOptions()); err != nil {
		return err
	}

	nsSet := make(map[string]any)
	for _, ns := range nss.Items {
		nsSet[ns.Name] = struct{}{}
	}

	var li ciliumv2.CiliumIdentityList
	if err := c.List(ctx, &li, subject.GetClientPodListOptions()); err != nil {
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

		if ns, ok := item.SecurityLabels["k8s:io.kubernetes.pod.namespace"]; ok {
			if _, ok := nsSet[ns]; !ok {
				continue
			}
		}
		e.labels = item.SecurityLabels
		items = append(items, e)
	}

	idEndpoints, err := getIdentityEndpoints(ctx, c)
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
func walkIdTree(w io.Writer, entries []idTreeEntry, idEndpoints map[uint32][]*ciliumv2.CiliumEndpoint, prefix string) error {
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
