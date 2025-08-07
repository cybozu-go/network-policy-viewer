package e2e

import (
	"fmt"
	"regexp"
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

	expectedAll := `{
  "k8s:app": [
    "local-path-provisioner",
    "ubuntu"
  ],
  "k8s:app.kubernetes.io/name": [
    "cilium-agent-proxy"
  ],
  "k8s:group": [
    "test"
  ],
  "k8s:io.cilium.k8s.policy.serviceaccount": [
    "coredns",
    "default",
    "local-path-provisioner-service-account",
    "ubuntu"
  ],
  "k8s:k8s-app": [
    "kube-dns"
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
	It("should show Security Identity label cardinality for all namespaces", func() {
		result := runViewerSafe(Default, nil, "id", "label", "-A", "-o=json")
		Expect(string(result)).To(Equal(expectedAll))
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

func testIdTree() {
	expected := `k8s:io.cilium.k8s.policy.cluster=default
k8s:io.kubernetes.pod.namespace=test
k8s:group=test
k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=test
k8s:io.cilium.k8s.policy.serviceaccount=default
k8s:test
├── l3-egress-explicit-deny-all
│   └── l3-egress-explicit-deny-all
├── l3-egress-implicit-deny-all
│   └── l3-egress-implicit-deny-all
├── l3-ingress-explicit-allow-all
│   ├── l3-ingress-explicit-allow-all
│   └── l3-ingress-explicit-allow-all
├── l3-ingress-explicit-deny-all
│   └── l3-ingress-explicit-deny-all
├── l3-ingress-implicit-deny-all
│   └── l3-ingress-implicit-deny-all
├── l4-egress-explicit-deny-any
│   └── l4-egress-explicit-deny-any
├── l4-egress-explicit-deny-tcp
│   └── l4-egress-explicit-deny-tcp
├── l4-ingress-all-allow-tcp
│   └── l4-ingress-all-allow-tcp
├── l4-ingress-explicit-allow-any
│   └── l4-ingress-explicit-allow-any
├── l4-ingress-explicit-allow-tcp
│   └── l4-ingress-explicit-allow-tcp
├── l4-ingress-explicit-deny-any
│   └── l4-ingress-explicit-deny-any
├── l4-ingress-explicit-deny-udp
│   └── l4-ingress-explicit-deny-udp
└── self
    ├── self
    └── self
`

	It("should show id tree", func() {
		podPattern, err := regexp.Compile("(?P<group>[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+)-[[:alnum:]]+-[[:alnum:]]+")
		Expect(err).NotTo(HaveOccurred())

		selfPattern, err := regexp.Compile("self-[[:alnum:]]+-[[:alnum:]]+")
		Expect(err).NotTo(HaveOccurred())

		result := runViewerSafe(Default, nil, "id", "tree", "-n=test")
		result = podPattern.ReplaceAll(result, []byte("${1}"))
		result = selfPattern.ReplaceAll(result, []byte("self"))
		Expect(string(result)).To(Equal(expected))
	})
}
