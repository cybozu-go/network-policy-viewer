package app

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var manifestRangeOptions struct {
	from string
	to   string
}

func init() {
	manifestRangeCmd.Flags().StringVar(&manifestRangeOptions.from, "from", "", "egress pod")
	manifestRangeCmd.Flags().StringVar(&manifestRangeOptions.to, "to", "", "ingress pod")
	manifestRangeCmd.RegisterFlagCompletionFunc("from", completeNamespacePods)
	manifestRangeCmd.RegisterFlagCompletionFunc("to", completeNamespacePods)
	manifestCmd.AddCommand(manifestRangeCmd)
}

var manifestRangeCmd = &cobra.Command{
	Use:   "range",
	Short: "List affected pods of a generated manifest",
	Long:  `List affected pods of a generated manifest`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManifestRange(context.Background(), cmd.OutOrStdout())
	},
}

type manifestRangeEntry struct {
	Part      string `json:"part"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func lessManifestRangeEntry(x, y *manifestRangeEntry) bool {
	ret := strings.Compare(x.Part, y.Part)
	if ret == 0 {
		ret = strings.Compare(x.Namespace, y.Namespace)
	}
	if ret == 0 {
		ret = strings.Compare(x.Name, y.Name)
	}
	return ret < 0
}

func runManifestRange(ctx context.Context, w io.Writer) error {
	if manifestRangeOptions.from == "" || manifestRangeOptions.to == "" {
		return errors.New("--from and --to options are required")
	}

	from, err := parseNamespacedName(manifestRangeOptions.from)
	if err != nil {
		return errors.New("--from and --to should be specified as NAMESPACE/POD")
	}

	to, err := parseNamespacedName(manifestRangeOptions.to)
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

	arr := make([]manifestRangeEntry, 0)
	sort.Slice(arr, func(i, j int) bool { return lessManifestRangeEntry(&arr[i], &arr[j]) })

	for _, ep := range idEndpoints[fromIdentity] {
		entry := manifestRangeEntry{
			Part:      "From",
			Namespace: ep.GetNamespace(),
			Name:      ep.GetName(),
		}
		arr = append(arr, entry)
	}
	for _, ep := range idEndpoints[toIdentity] {
		entry := manifestRangeEntry{
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
