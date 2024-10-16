package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
)

func init() {
	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list network policies applied to a pod",
	Long:  `List network policies applied to a pod`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runList(context.Background(), cmd.OutOrStdout(), args[0])
	},
}

const (
	directionEgress  = "EGRESS"
	directionIngress = "INGRESS"
)

type derivedFromEntry struct {
	Direction string `json:"direction"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func lessDerivedFromEntry(x, y *derivedFromEntry) bool {
	if strings.Compare(x.Direction, y.Direction) < 0 {
		return true
	}
	if x.Kind != y.Kind {
		return strings.Compare(x.Kind, y.Kind) < 0
	}
	if x.Namespace != y.Namespace {
		return strings.Compare(x.Namespace, y.Namespace) < 0
	}
	if x.Name != y.Name {
		return strings.Compare(x.Name, y.Name) < 0
	}
	return false
}

func parseDerivedFromEntry(input []string, direction string) derivedFromEntry {
	val := derivedFromEntry{
		Direction: direction,
	}
	for _, s := range input {
		switch {
		case strings.Contains(s, "k8s:io.cilium.k8s.policy.derived-from"):
			val.Kind = strings.Split(s, "=")[1]
		case strings.Contains(s, "k8s:io.cilium.k8s.policy.namespace"):
			val.Namespace = strings.Split(s, "=")[1]
		case strings.Contains(s, "k8s:io.cilium.k8s.policy.name"):
			val.Name = strings.Split(s, "=")[1]
		}
	}
	return val
}

func runList(ctx context.Context, w io.Writer, name string) error {
	_, dynamicClient, client, err := createClients(ctx, name)
	if err != nil {
		return err
	}

	endpointID, err := getPodEndpointID(ctx, dynamicClient, rootOptions.namespace, name)
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

	policySet := make(map[derivedFromEntry]struct{})

	ingressRules := response.Payload.Status.Policy.Realized.L4.Ingress
	for _, rule := range ingressRules {
		for _, r := range rule.DerivedFromRules {
			entry := parseDerivedFromEntry(r, directionIngress)
			policySet[entry] = struct{}{}
		}
	}

	egressRules := response.Payload.Status.Policy.Realized.L4.Egress
	for _, rule := range egressRules {
		for _, r := range rule.DerivedFromRules {
			entry := parseDerivedFromEntry(r, directionEgress)
			policySet[entry] = struct{}{}
		}
	}

	policyList := maps.Keys(policySet)
	sort.Slice(policyList, func(i, j int) bool { return compareDerivedFromEntry(&policyList[i], &policyList[j]) })

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
		if !rootOptions.noHeaders {
			_, err := tw.Write([]byte("DIRECTION\tKIND\tNAMESPACE\tNAME\n"))
			if err != nil {
				return err
			}
		}
		for _, p := range policyList {
			_, err := tw.Write([]byte(fmt.Sprintf("%v\t%v\t%v\t%v\n", p.Direction, p.Kind, p.Namespace, p.Name)))
			if err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
