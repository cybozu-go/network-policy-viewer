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
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
EGRESS,CiliumNetworkPolicy,default,l3-egress
EGRESS,CiliumNetworkPolicy,default,l4-egress
INGRESS,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l3-ingress-explicit-allow",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-ingress-explicit-allow`,
		},
		{
			Selector: "test=l3-ingress-implicit-deny",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-ingress-explicit-deny`,
		},
		{
			Selector: "test=l3-egress-implicit-deny",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l3-egress-explicit-deny",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-any",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l4-ingress-explicit-allow-any`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-tcp",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l4-ingress-explicit-allow-tcp`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-any",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l4-ingress-explicit-deny-any`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-udp",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l4-ingress-explicit-deny-udp`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-any",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-tcp",
			Expected: `EGRESS,CiliumNetworkPolicy,default,l3-baseline
INGRESS,CiliumNetworkPolicy,default,l3-baseline`,
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
