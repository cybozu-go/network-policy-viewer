package app

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
		return runDump(context.Background(), cmd.OutOrStdout(), args[0])
	},
	ValidArgsFunction: completePods,
}

func runDump(ctx context.Context, w io.Writer, name string) error {
	clientset, dynamicClient, err := createK8sClients()
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

	url := proxyEndpoint + fmt.Sprintf("/v1/endpoint/%d", endpointID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
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
	buf.WriteTo(w)
	return nil
}
