package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
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
	_, dynamicClient, err := createK8sClients()
	if err != nil {
		return err
	}

	subIdentity, err := getPodIdentity(ctx, dynamicClient, sub.Namespace, sub.Name)
	if err != nil {
		return err
	}

	subResource, err := dynamicClient.Resource(gvrIdentity).Get(ctx, strconv.Itoa(int(subIdentity)), metav1.GetOptions{})
	if err != nil {
		return err
	}

	subLabels, ok, err := unstructured.NestedStringMap(subResource.Object, "security-labels")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("pod %s/%s is not assigned security labels", sub.Namespace, sub.Name)
	}

	objIdentity, err := getPodIdentity(ctx, dynamicClient, obj.Namespace, obj.Name)
	if err != nil {
		return err
	}

	objResource, err := dynamicClient.Resource(gvrIdentity).Get(ctx, strconv.Itoa(int(objIdentity)), metav1.GetOptions{})
	if err != nil {
		return err
	}

	objLabels, ok, err := unstructured.NestedStringMap(objResource.Object, "security-labels")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("pod %s/%s is not assigned security labels", obj.Namespace, obj.Name)
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
	manifest.SetGroupVersionKind(gvkNetworkPolicy)
	manifest.SetNamespace(sub.Namespace)
	manifest.SetName(policyName)
	err = unstructured.SetNestedStringMap(manifest.Object, subLabels, "spec", "endpointSelector", "matchLabels")
	if err != nil {
		return err
	}

	objMap := make(map[string]any)
	for k, v := range objLabels {
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
