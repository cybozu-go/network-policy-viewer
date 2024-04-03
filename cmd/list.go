package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/spf13/cobra"
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
		return runList(context.Background(), args[0])
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

func runList(ctx context.Context, name string) error {
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

	policyList := make([]derivedFromEntry, 0)

	ingressRules := response.Payload.Status.Policy.Realized.L4.Ingress
	for _, rule := range ingressRules {
		for _, r := range rule.DerivedFromRules {
			policyList = append(policyList, parseDerivedFromEntry(r, directionIngress))
		}
	}

	egressRules := response.Payload.Status.Policy.Realized.L4.Egress
	for _, rule := range egressRules {
		for _, r := range rule.DerivedFromRules {
			policyList = append(policyList, parseDerivedFromEntry(r, directionEgress))
		}
	}

	text, err := json.MarshalIndent(policyList, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(text))
	return nil
}
