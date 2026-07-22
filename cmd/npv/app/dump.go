package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/spf13/cobra"

	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
	"github.com/cybozu-go/network-policy-viewer/pkg/proxy"
	"github.com/cybozu-go/network-policy-viewer/pkg/subject"
)

func init() {
	addNamespaceOption(dumpCmd)
	rootCmd.AddCommand(dumpCmd)
}

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump endpoint status",
	Long:  `Dump endpoint status`,

	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDump(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0])
	},
	ValidArgsFunction: completePods,
}

func runDump(ctx context.Context, stdout, stderr io.Writer, name string) error {
	c, err := k8s.NewClient()
	if err != nil {
		return err
	}

	selector := subject.GetSelectorConfig()

	client, err := proxy.CreateCiliumClient(ctx, stderr, c, selector.Namespace, name)
	if err != nil {
		return err
	}

	data, err := client.DumpEndpoint(ctx, selector.Namespace, name)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return err
	}
	if _, err := buf.WriteTo(stdout); err != nil {
		return err
	}
	return nil
}
