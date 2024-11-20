package app

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var manifestBlastOptions struct {
	from string
	to   string
}

func init() {
	manifestBlastCmd.Flags().StringVar(&manifestBlastOptions.from, "from", "", "egress pod")
	manifestBlastCmd.Flags().StringVar(&manifestBlastOptions.to, "to", "", "ingress pod")
	manifestCmd.AddCommand(manifestBlastCmd)
}

var manifestBlastCmd = &cobra.Command{
	Use:   "blast",
	Short: "Show blast radius of a generated manifest",
	Long:  `Show blast radius of a generated manifest`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManifestBlast(context.Background(), cmd.OutOrStdout())
	},
}

type manifestBlastEntry struct {
	Direction string `json:"direction"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func lessManifestBlastEntry(x, y *manifestBlastEntry) bool {
	ret := strings.Compare(x.Direction, y.Direction)
	if ret == 0 {
		ret = strings.Compare(x.Namespace, y.Namespace)
	}
	if ret == 0 {
		ret = strings.Compare(x.Name, y.Name)
	}
	return ret < 0
}

func runManifestBlast(ctx context.Context, w io.Writer) error {
	if manifestBlastOptions.from == "" || manifestBlastOptions.to == "" {
		return errors.New("--from and --to options are required")
	}

	fromSlice := strings.Split(manifestBlastOptions.from, "/")
	toSlice := strings.Split(manifestBlastOptions.to, "/")
	if len(fromSlice) != 2 || len(toSlice) != 2 {
		return errors.New("--from and --to should be NAMESPACE/POD")
	}

	_, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	fromIdentity, err := getPodIdentity(ctx, dynamicClient, fromSlice[0], fromSlice[1])
	if err != nil {
		return err
	}

	toIdentity, err := getPodIdentity(ctx, dynamicClient, toSlice[0], toSlice[1])
	if err != nil {
		return err
	}

	idEndpoints, err := getIdentityEndpoints(ctx, dynamicClient)
	if err != nil {
		return err
	}

	arr := make([]manifestBlastEntry, 0)
	sort.Slice(arr, func(i, j int) bool { return lessManifestBlastEntry(&arr[i], &arr[j]) })

	for _, ep := range idEndpoints[int(fromIdentity)] {
		entry := manifestBlastEntry{
			Direction: directionEgress,
			Namespace: ep.GetNamespace(),
			Name:      ep.GetName(),
		}
		arr = append(arr, entry)
	}
	for _, ep := range idEndpoints[int(toIdentity)] {
		entry := manifestBlastEntry{
			Direction: directionIngress,
			Namespace: ep.GetNamespace(),
			Name:      ep.GetName(),
		}
		arr = append(arr, entry)
	}
	return writeSimpleOrJson(w, arr, []string{"DIRECTION", "NAMESPACE", "NAME"}, len(arr), func(index int) []any {
		ep := arr[index]
		return []any{ep.Direction, ep.Namespace, ep.Name}
	})
}
