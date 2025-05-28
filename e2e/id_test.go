package e2e

import (
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testIdLabel() {
	expected := `{
  "k8s:group": [
    "test"
  ],
  "k8s:io.cilium.k8s.policy.serviceaccount": [
    "default"
  ],
  "k8s:test": [
    "l3-egress-explicit-deny-all",
    "l3-egress-implicit-deny-all",
    "l3-ingress-explicit-allow-all",
    "l3-ingress-explicit-deny-all",
    "l3-ingress-implicit-deny-all",
    "l4-egress-explicit-deny-any",
    "l4-egress-explicit-deny-tcp",
    "l4-ingress-all-allow-tcp",
    "l4-ingress-explicit-allow-any",
    "l4-ingress-explicit-allow-tcp",
    "l4-ingress-explicit-deny-any",
    "l4-ingress-explicit-deny-udp",
    "self"
  ]
}
`
	It("should show Security Identity label cardinality", func() {
		result := runViewerSafe(Default, nil, "id", "label", "-n=test", "-o=json")
		Expect(string(result)).To(Equal(expected))
	})
}

func testIdSummary() {
	cases := []struct {
		Namespace string
		Count     int
	}{
		{
			Namespace: "cilium-agent-proxy",
			Count:     1,
		},
		{
			Namespace: "default",
			Count:     1,
		},
		{
			Namespace: "kube-system",
			Count:     1,
		},
		{
			Namespace: "local-path-storage",
			Count:     1,
		},
		{
			Namespace: "test",
			Count:     13,
		},
	}
	It("should show ID summary", func() {
		for _, c := range cases {
			resultData := runViewerSafe(Default, nil, "id", "summary", "-o=json")
			resultData = jqSafe(Default, resultData, "-r", fmt.Sprintf(`."%s"`, c.Namespace))
			result, err := strconv.Atoi(string(resultData))
			Expect(err).NotTo(HaveOccurred())

			expected := c.Count

			// Multiple CiliumIdentities may be generated for a same set of security-relevant labels
			Expect(result).To(BeNumerically(">=", expected), "compare failed. namespace: %s\nactual: %d\nexpected: %d", result, expected)
		}
	})
}
