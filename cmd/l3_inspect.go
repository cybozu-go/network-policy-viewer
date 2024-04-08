package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	l3Cmd.AddCommand(l3InspectCmd)
}

var l3InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "",
	Long:  ``,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runL3Inspect(context.Background(), cmd.OutOrStdout(), args[0])
	},
}

type l3InspectEntry struct {
	Direction string            `json:"direction"`
	Allowed   bool              `json:"allowed"`
	Namespace string            `json:"namespace"`
	Identity  int64             `json:"identity"`
	Labels    map[string]string `json:"labels"`
}

func buildL3InspectEntry(dict *unstructured.UnstructuredList, id int64, direction string, allowed bool) (l3InspectEntry, error) {
	val := l3InspectEntry{
		Direction: direction,
		Allowed:   allowed,
		Identity:  id,
	}

	// https://docs.cilium.io/en/latest/gettingstarted/terminology/#special-identities
	switch id {
	case 0:
		val.Labels = map[string]string{"!! reserved": "unknown"}
		return val, nil
	case 1:
		val.Labels = map[string]string{"!! reserved": "host"}
		return val, nil
	case 2:
		val.Labels = map[string]string{"!! reserved": "world"}
		return val, nil
	case 3:
		val.Labels = map[string]string{"!! reserved": "unmanaged"}
		return val, nil
	case 4:
		val.Labels = map[string]string{"!! reserved": "health"}
		return val, nil
	case 5:
		val.Labels = map[string]string{"!! reserved": "init"}
		return val, nil
	case 6:
		val.Labels = map[string]string{"!! reserved": "remote-node"}
		return val, nil
	case 7:
		val.Labels = map[string]string{"!! reserved": "kube-apiserver"}
		return val, nil
	case 8:
		val.Labels = map[string]string{"!! reserved": "ingress"}
		return val, nil
	}

	obj := findCiliumID(dict, id)
	if obj == nil {
		return l3InspectEntry{}, fmt.Errorf("CiliumID is not found for ID: %d", id)
	}

	labels, found, err := unstructured.NestedStringMap(obj.Object, "security-labels")
	if !found {
		return l3InspectEntry{}, fmt.Errorf("security label is missing for CiliumID: %d", id)
	}
	if err != nil {
		return l3InspectEntry{}, err
	}
	val.Labels = labels

	ns, ok := labels["k8s:io.kubernetes.pod.namespace"]
	if !ok {
		return l3InspectEntry{}, fmt.Errorf("namespace label is missing for CiliumID: %d", id)
	}
	val.Namespace = ns
	return val, nil
}

func compareL3InspectEntry(x, y *l3InspectEntry) bool {
	if x.Direction != y.Direction {
		return strings.Compare(x.Direction, y.Direction) < 0
	}
	if x.Allowed != y.Allowed {
		return x.Allowed
	}
	if x.Namespace != y.Namespace {
		return strings.Compare(x.Namespace, y.Namespace) < 0
	}
	if x.Identity != y.Identity {
		return x.Identity < y.Identity
	}
	// Labels should differ between identities
	return false
}

func runL3Inspect(ctx context.Context, w io.Writer, name string) error {
	_, dynamicClient, client, err := createClients(ctx, name)
	if err != nil {
		return err
	}

	ciliumIDs, err := listCiliumIDs(ctx, dynamicClient)
	if err != nil {
		return err
	}

	endpointID, _, err := getPodEndpointID(ctx, dynamicClient, rootOptions.namespace, name)
	if err != nil {
		return err
	}

	params := endpoint.GetEndpointIDParams{
		Context: ctx,
		ID:      strconv.FormatInt(endpointID, 10),
	}
	response, err := client.Endpoint.GetEndpointID(&params)
	if err != nil {
		return err
	}

	policyList := make([]l3InspectEntry, 0)

	allowedEgress := response.Payload.Status.Policy.Realized.AllowedEgressIdentities
	for _, id := range allowedEgress {
		entry, err := buildL3InspectEntry(ciliumIDs, id, directionEgress, true)
		if err != nil {
			return err
		}
		policyList = append(policyList, entry)
	}

	deniedEgress := response.Payload.Status.Policy.Realized.DeniedEgressIdentities
	for _, id := range deniedEgress {
		entry, err := buildL3InspectEntry(ciliumIDs, id, directionEgress, false)
		if err != nil {
			return err
		}
		policyList = append(policyList, entry)
	}

	allowedIngress := response.Payload.Status.Policy.Realized.AllowedIngressIdentities
	for _, id := range allowedIngress {
		entry, err := buildL3InspectEntry(ciliumIDs, id, directionIngress, true)
		if err != nil {
			return err
		}
		policyList = append(policyList, entry)
	}

	deniedIngress := response.Payload.Status.Policy.Realized.DeniedIngressIdentities
	for _, id := range deniedIngress {
		entry, err := buildL3InspectEntry(ciliumIDs, id, directionIngress, false)
		if err != nil {
			return err
		}
		policyList = append(policyList, entry)
	}

	sort.Slice(policyList, func(i, j int) bool { return compareL3InspectEntry(&policyList[i], &policyList[j]) })

	switch rootOptions.output {
	case OutputJson:
		text, err := json.MarshalIndent(policyList, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(text)
		return err
	case OutputSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		_, err := tw.Write([]byte("DIRECTION\tALLOWED\tNAMESPACE\tIDENTITY\tLABELS\n"))
		if err != nil {
			return err
		}
		for _, p := range policyList {
			keys := maps.Keys(p.Labels)
			slices.Sort(keys)
			for i, k := range keys {
				switch i {
				case 0:
					_, err := tw.Write([]byte(fmt.Sprintf("%v\t%v\t%v\t%v\t%v=%v\n", p.Direction, p.Allowed, p.Namespace, p.Identity, k, p.Labels[k])))
					if err != nil {
						return err
					}
				default:
					_, err := tw.Write([]byte(fmt.Sprintf("\t\t\t\t%v=%v\n", k, p.Labels[k])))
					if err != nil {
						return err
					}
				}
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
