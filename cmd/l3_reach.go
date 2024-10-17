package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/spf13/cobra"
)

var l3ReachOptions struct {
	to string
}

func init() {
	l3ReachCmd.Flags().StringVar(&l3ReachOptions.to, "to", "", "target pod namespace/name")
	l3Cmd.AddCommand(l3ReachCmd)
}

const (
	typeExplicit = "EXPLICIT"
	typeImplicit = "IMPLICIT"
)

type l3ReachEntry struct {
	Direction string `json:"direction"`
	Allowed   bool   `json:"allowed"`
	Type      string `json:"type"`
}

var l3ReachCmd = &cobra.Command{
	Use:   "reach",
	Short: "",
	Long:  ``,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		to := l3ReachOptions.to
		if to == "" {
			return errors.New("please specify --to parameter")
		}
		toList := strings.Split(to, "/")
		if len(toList) != 2 {
			return errors.New("--to must be NAMESPACE/NAME")
		}
		return runL3Reach(context.Background(), cmd.OutOrStdout(), args[0], toList[0], toList[1])
	},
}

func runL3Reach(ctx context.Context, w io.Writer, name, toNamespace, toName string) error {
	clientset, dynamicClient, senderClient, err := createClients(ctx, name)
	if err != nil {
		return err
	}
	receiverClient, err := createCiliumClient(ctx, clientset, toNamespace, toName)
	if err != nil {
		return err
	}

	senderEndpointID, senderIdentity, err := getPodEndpointID(ctx, dynamicClient, rootOptions.namespace, name)
	if err != nil {
		return err
	}

	receiverEndpointID, receiverIdentity, err := getPodEndpointID(ctx, dynamicClient, toNamespace, toName)
	if err != nil {
		return err
	}

	// Check egress rule to see if sender can send packets to receiver
	params := endpoint.GetEndpointIDParams{
		Context: ctx,
		ID:      strconv.FormatInt(senderEndpointID, 10),
	}
	senderResponse, err := senderClient.Endpoint.GetEndpointID(&params)
	if err != nil {
		return err
	}

	allowedEgressIdentities := senderResponse.Payload.Status.Policy.Realized.AllowedEgressIdentities
	deniedEgressIdentities := senderResponse.Payload.Status.Policy.Realized.DeniedEgressIdentities
	egressOK := slices.Contains(allowedEgressIdentities, receiverIdentity)
	egressDeny := slices.Contains(deniedEgressIdentities, receiverIdentity)
	egressType := typeExplicit
	if !egressOK && !egressDeny {
		egressType = typeImplicit
	}

	// Check ingress rule to see if receiver can receive packets from sender
	params = endpoint.GetEndpointIDParams{
		Context: ctx,
		ID:      strconv.FormatInt(receiverEndpointID, 10),
	}
	receiverResponse, err := receiverClient.Endpoint.GetEndpointID(&params)
	if err != nil {
		return err
	}

	allowedIngressIdentities := receiverResponse.Payload.Status.Policy.Realized.AllowedIngressIdentities
	deniedIngressIdentities := receiverResponse.Payload.Status.Policy.Realized.DeniedIngressIdentities
	ingressOK := slices.Contains(allowedIngressIdentities, senderIdentity)
	ingressDeny := slices.Contains(deniedIngressIdentities, senderIdentity)
	ingressType := typeExplicit
	if !ingressOK && !ingressDeny {
		ingressType = typeImplicit
	}

	policyList := []l3ReachEntry{
		{
			Direction: directionEgress,
			Allowed:   egressOK,
			Type:      egressType,
		},
		{
			Direction: directionIngress,
			Allowed:   ingressOK,
			Type:      ingressType,
		},
	}

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
		_, err := tw.Write([]byte("DIRECTION\tALLOWED\tTYPE\n"))
		if err != nil {
			return err
		}
		for _, p := range policyList {
			_, err := tw.Write([]byte(fmt.Sprintf("%v\t%v\t%v\n", p.Direction, p.Allowed, p.Type)))
			if err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
