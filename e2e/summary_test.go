package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testSummary() {
	expected := `l3-egress-explicit-deny-all,1,0,0,0
l3-egress-implicit-deny-all,1,0,0,0
l3-ingress-explicit-allow-all,2,0,0,0
l3-ingress-explicit-allow-all,2,0,0,0
l3-ingress-explicit-deny-all,1,1,0,0
l3-ingress-implicit-deny-all,1,0,0,0
l4-egress-explicit-deny-any,1,0,0,0
l4-egress-explicit-deny-tcp,1,0,0,0
l4-ingress-all-allow-tcp,3,0,0,0
l4-ingress-explicit-allow-any,4,0,0,0
l4-ingress-explicit-allow-tcp,2,0,0,0
l4-ingress-explicit-deny-any,1,3,0,0
l4-ingress-explicit-deny-udp,1,1,0,0
self,1,0,17,8
self,1,0,17,8`

	It("should show summary", func() {
		result := runViewerSafe(Default, nil, "summary", "-o=json", "-n=test")
		// remove hash suffix from pod names
		result = jqSafe(Default, result, "-r", `[.[] | .name = (.name | split("-") | .[0:5] | join("-"))]`)
		result = jqSafe(Default, result, "-r", `[.[] | .name = (.name | if startswith("self") then "self" else . end)]`)
		result = jqSafe(Default, result, "-r", `.[] | [.name, .ingress_allow, .ingress_deny, .egress_allow, .egress_deny] | @csv`)
		resultString := strings.Replace(string(result), `"`, "", -1)
		Expect(resultString).To(Equal(expected), "compare failed.\nactual: %s\nexpected: %s", resultString, expected)
	})
}

func testSummaryAll() {
	It("should show summary for all namespaces", func() {
		data := kubectlSafe(Default, nil, "get", "cep", "-A", "-o=jsonpath={.items[*].metadata.name}")
		ceps := strings.Fields(string(data))

		result := runViewerSafe(Default, nil, "summary", "-A", "-o=json")
		result = jqSafe(Default, result, "-r", ".[].name")
		summaryPods := strings.Fields(string(result))
		Expect(ceps).To(Equal(summaryPods))
	})
}

func testSummaryNode() {
	It("should show summary per node", func() {
		data := kubectlSafe(Default, nil, "get", "node", "-o=jsonpath={.items[*].metadata.name}")
		nodes := strings.Fields(string(data))

		data = kubectlSafe(Default, nil, "get", "cep", "-A", "-o=jsonpath={.items[*].metadata.name}")
		ceps := strings.Fields(string(data))

		for _, node := range nodes {
			data = kubectlSafe(Default, nil, "get", "pod", "-A", "--field-selector=spec.nodeName="+node, "-o=jsonpath={.items[*].metadata.name}")
			nodePods := makeIntersection(strings.Fields(string(data)), ceps)

			result := runViewerSafe(Default, nil, "summary", "--node="+node, "-o=json")
			result = jqSafe(Default, result, "-r", ".[].name")
			summaryPods := strings.Fields(string(result))
			Expect(nodePods).To(Equal(summaryPods))
		}
	})
}
