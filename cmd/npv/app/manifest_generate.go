package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/cybozu-go/network-policy-viewer/pkg/gvk"
	"github.com/cybozu-go/network-policy-viewer/pkg/k8s"
)

var manifestGenerateOptions struct {
	name    string
	egress  bool
	ingress bool
	allow   bool
	deny    bool
	from    string
	to      string
}

func init() {
	manifestGenerateCmd.Flags().StringVar(&manifestGenerateOptions.name, "name", "", "resource name")
	manifestGenerateCmd.Flags().BoolVar(&manifestGenerateOptions.egress, "egress", false, "generate egress rule")
	manifestGenerateCmd.Flags().BoolVar(&manifestGenerateOptions.ingress, "ingress", false, "generate ingress rule")
	manifestGenerateCmd.Flags().BoolVar(&manifestGenerateOptions.allow, "allow", false, "generate allow rule")
	manifestGenerateCmd.Flags().BoolVar(&manifestGenerateOptions.deny, "deny", false, "generate deny rule")
	manifestGenerateCmd.Flags().StringVar(&manifestGenerateOptions.from, "from", "", "egress pod")
	manifestGenerateCmd.Flags().StringVar(&manifestGenerateOptions.to, "to", "", "ingress pod")
	if err := manifestGenerateCmd.RegisterFlagCompletionFunc("from", completeNamespacePods); err != nil {
		panic(err)
	}
	if err := manifestGenerateCmd.RegisterFlagCompletionFunc("to", completeNamespacePods); err != nil {
		panic(err)
	}
	manifestCmd.AddCommand(manifestGenerateCmd)
}

var manifestGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate CiliumNetworkPolicy",
	Long:  `Generate CiliumNetworkPolicy`,

	Args: cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManifestGenerate(context.Background(), cmd.OutOrStdout())
	},
}

func runManifestGenerate(ctx context.Context, w io.Writer) error {
	egress := manifestGenerateOptions.egress
	ingress := manifestGenerateOptions.ingress
	allow := manifestGenerateOptions.allow
	deny := manifestGenerateOptions.deny
	from := manifestGenerateOptions.from
	to := manifestGenerateOptions.to

	if egress == ingress {
		return errors.New("one of --egress or --ingress should be specified")
	}
	if allow == deny {
		return errors.New("one of --allow or --deny should be specified")
	}

	sub, err := parseNamespacedName(from)
	if err != nil {
		return errors.New("--from and --to should be specified as NAMESPACE/POD")
	}

	obj, err := parseNamespacedName(to)
	if err != nil {
		return errors.New("--from and --to should be specified as NAMESPACE/POD")
	}

	if ingress {
		sub, obj = obj, sub
	}

	// Parameters are all up, let's start querying API server
	c, err := k8s.NewClient()
	if err != nil {
		return err
	}

	subIdentity, err := getPodIdentity(ctx, c, sub.Namespace, sub.Name)
	if err != nil {
		return err
	}

	objIdentity, err := getPodIdentity(ctx, c, obj.Namespace, obj.Name)
	if err != nil {
		return err
	}

	var subResource, objResource ciliumv2.CiliumIdentity
	if err := c.Get(ctx, types.NamespacedName{Name: strconv.Itoa(int(subIdentity))}, &subResource); err != nil {
		return err
	}

	if err := c.Get(ctx, types.NamespacedName{Name: strconv.Itoa(int(objIdentity))}, &objResource); err != nil {
		return err
	}

	policyName := manifestGenerateOptions.name
	if policyName == "" {
		direction := "egress"
		policy := "allow"
		if ingress {
			direction = "ingress"
		}
		if deny {
			policy = "deny"
		}
		policyName = fmt.Sprintf("%s-%s-%d-%d", direction, policy, subIdentity, objIdentity)
	}

	var manifest unstructured.Unstructured
	manifest.SetGroupVersionKind(gvk.NetworkPolicy)
	manifest.SetNamespace(sub.Namespace)
	manifest.SetName(policyName)
	err = unstructured.SetNestedStringMap(manifest.Object, subResource.SecurityLabels, "spec", "endpointSelector", "matchLabels")
	if err != nil {
		return err
	}

	objMap := make(map[string]any)
	for k, v := range objResource.SecurityLabels {
		objMap[k] = v
	}

	var section, field string
	switch {
	case egress && allow:
		section = "egress"
		field = "toEndpoints"
	case egress && deny:
		section = "egressDeny"
		field = "toEndpoints"
	case ingress && allow:
		section = "ingress"
		field = "fromEndpoints"
	case ingress && deny:
		section = "ingressDeny"
		field = "fromEndpoints"
	}

	err = unstructured.SetNestedField(manifest.Object, []any{
		map[string]any{
			field: []any{
				map[string]any{
					"matchLabels": objMap,
				},
			},
		},
	}, "spec", section)
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(manifest.Object)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s", string(data)); err != nil {
		return err
	}
	return nil
}
