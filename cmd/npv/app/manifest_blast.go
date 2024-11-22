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
	Part      string `json:"part"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func lessManifestBlastEntry(x, y *manifestBlastEntry) bool {
	ret := strings.Compare(x.Part, y.Part)
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

	from, err := parseNamespacedName(manifestBlastOptions.from)
	if err != nil {
		return errors.New("--from and --to should be specified as NAMESPACE/POD")
	}

	to, err := parseNamespacedName(manifestBlastOptions.to)
	if err != nil {
		return errors.New("--from and --to should be specified as NAMESPACE/POD")
	}

	_, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	fromIdentity, err := getPodIdentity(ctx, dynamicClient, from.Namespace, from.Name)
	if err != nil {
		return err
	}

	toIdentity, err := getPodIdentity(ctx, dynamicClient, to.Namespace, to.Name)
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
			Part:      "From",
			Namespace: ep.GetNamespace(),
			Name:      ep.GetName(),
		}
		arr = append(arr, entry)
	}
	for _, ep := range idEndpoints[int(toIdentity)] {
		entry := manifestBlastEntry{
			Part:      "To",
			Namespace: ep.GetNamespace(),
			Name:      ep.GetName(),
		}
		arr = append(arr, entry)
	}
	return writeSimpleOrJson(w, arr, []string{"PART", "NAMESPACE", "NAME"}, len(arr), func(index int) []any {
		ep := arr[index]
		return []any{ep.Part, ep.Namespace, ep.Name}
	})
}
