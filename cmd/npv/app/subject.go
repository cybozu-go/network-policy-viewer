package app

import (
	"context"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/slices"
	"github.com/spf13/cobra"
)

func init() {
	addGroupOption(subjectCmd)
	addSelectorOption(subjectCmd)
	rootCmd.AddCommand(subjectCmd)
}

var subjectCmd = &cobra.Command{
	Use:   "subject",
	Short: "list subjects with current selector and group options",
	Long:  `List subjects with current selector and group options`,

	Args: cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return runSubject(context.Background(), cmd.OutOrStdout(), "")
		} else {
			return runSubject(context.Background(), cmd.OutOrStdout(), args[0])
		}
	},
	ValidArgsFunction: completePods,
}

func runSubject(ctx context.Context, stdout io.Writer, name string) error {
	clientset, _, err := createK8sClients()
	if err != nil {
		return fmt.Errorf("failed to create k8s clients: %w", err)
	}

	pods, err := listSubjectPods(ctx, clientset, name)
	if err != nil {
		return err
	}

	subjects := make([]string, len(pods))
	for i, p := range pods {
		subjects[i] = getPodSubject(p.Namespace, p.Name)
	}
	subjects = slices.Unique(subjects)

	for _, s := range subjects {
		fmt.Fprintln(stdout, s)
	}
	return nil
}
