package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
		return runDump(context.Background(), args[0])
	},
}

func runDump(ctx context.Context, name string) error {
	clientset, dynamicClient, _, err := createClients(ctx, name)
	if err != nil {
		return err
	}

	endpointID, err := getPodEndpointID(ctx, dynamicClient, rootOptions.namespace, name)
	if err != nil {
		return err
	}

	proxyEndpoint, err := getProxyEndpoint(ctx, clientset, rootOptions.namespace, name)
	if err != nil {
		return err
	}

	resp, err := http.Get(proxyEndpoint + fmt.Sprintf("/v1/endpoint/%d", endpointID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	json.Indent(&buf, data, "", "  ")
	fmt.Println(buf.String())
	return nil
}
