package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testList() {
	cases := []struct {
		Selector string
		Expected string
	}{
		{
			Selector: "test=self",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Egress,CiliumNetworkPolicy,default,l3-egress
Egress,CiliumNetworkPolicy,default,l4-egress
Ingress,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l3-ingress-explicit-allow",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-ingress-explicit-allow`,
		},
		{
			Selector: "test=l3-ingress-implicit-deny",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-ingress-explicit-deny`,
		},
		{
			Selector: "test=l3-egress-implicit-deny",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l3-egress-explicit-deny",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-any",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l4-ingress-explicit-allow-any`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-tcp",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l4-ingress-explicit-allow-tcp`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-any",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l4-ingress-explicit-deny-any`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-udp",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l4-ingress-explicit-deny-udp`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-any",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-tcp",
			Expected: `Egress,CiliumNetworkPolicy,default,l3-baseline
Ingress,CiliumNetworkPolicy,default,l3-baseline`,
		},
	}

	It("should list applied policies", func() {
		for _, c := range cases {
			podName := onePodByLabelSelector(Default, "default", c.Selector)
			result := runViewerSafe(Default, nil, "list", "-o=json", "--no-headers", podName)
			result = jqSafe(Default, result, "-r", ".[] | [.direction, .kind, .namespace, .name] | @csv")
			resultString := strings.Replace(string(result), `"`, "", -1)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s, actual: %s, expected: %s", c.Selector, resultString, c.Expected)
		}
	})
}
