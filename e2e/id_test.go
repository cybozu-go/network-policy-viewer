package e2e

import (
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
	expected := `{"default":1,"kube-system":2,"local-path-storage":1,"test":12}`
	It("should show ID summary", func() {
		result := runViewerSafe(Default, nil, "id", "summary", "-o=json")
		result = jqSafe(Default, result, "-c")
		Expect(string(result)).To(Equal(expected), "compare failed.\nactual: %s\nexpected: %s", string(result), expected)
	})
}
