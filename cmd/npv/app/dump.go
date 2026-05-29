package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(dumpCmd)
}

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dump endpoint status",
	Long:  `Dump endpoint status`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDump(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0])
	},
	ValidArgsFunction: completePods,
}

func runDump(ctx context.Context, stdout, stderr io.Writer, name string) error {
	clientset, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	endpointID, err := getPodEndpointID(ctx, dynamicClient, rootOptions.namespace, name)
	if err != nil {
		return err
	}

	client, err := createCiliumClient(ctx, stderr, clientset, rootOptions.namespace, name)
	if err != nil {
		return err
	}

	data, err := client.dumpEndpoint(ctx, endpointID)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	json.Indent(&buf, data, "", "  ")
	buf.WriteTo(stdout)
	return nil
}
