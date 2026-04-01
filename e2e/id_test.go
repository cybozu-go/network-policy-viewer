package e2e

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testIdTree() {
	It("should handle namespace selector", func() {
		expected := `k8s:io.cilium.k8s.policy.cluster: default
k8s:io.kubernetes.pod.namespace
├── test
│   k8s:group: test
│   k8s:io.cilium.k8s.namespace.labels.group: test
│   k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
│   k8s:io.cilium.k8s.policy.serviceaccount: default
│   k8s:test: self
│   ├── [Pod] self
│   └── [Pod] self
├── test-l3
│   k8s:group: test
│   k8s:io.cilium.k8s.namespace.labels.group: test
│   k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
│   k8s:io.cilium.k8s.policy.serviceaccount: default
│   k8s:test
│   ├── l3-egress-explicit-deny-all
│   │   └── [Pod] l3-egress-explicit-deny-all
│   ├── l3-egress-implicit-deny-all
│   │   └── [Pod] l3-egress-implicit-deny-all
│   ├── l3-ingress-explicit-allow-all
│   │   ├── [Pod] l3-ingress-explicit-allow-all
│   │   └── [Pod] l3-ingress-explicit-allow-all
│   ├── l3-ingress-explicit-deny-all
│   │   └── [Pod] l3-ingress-explicit-deny-all
│   └── l3-ingress-implicit-deny-all
│       └── [Pod] l3-ingress-implicit-deny-all
└── test-l4
    k8s:group: test
    k8s:io.cilium.k8s.namespace.labels.group: test
    k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l4
    k8s:io.cilium.k8s.policy.serviceaccount: default
    k8s:test
    ├── l4-egress-explicit-deny-any
    │   └── [Pod] l4-egress-explicit-deny-any
    ├── l4-egress-explicit-deny-tcp
    │   └── [Pod] l4-egress-explicit-deny-tcp
    ├── l4-ingress-all-allow-tcp
    │   └── [Pod] l4-ingress-all-allow-tcp
    ├── l4-ingress-explicit-allow-any
    │   └── [Pod] l4-ingress-explicit-allow-any
    ├── l4-ingress-explicit-allow-tcp
    │   └── [Pod] l4-ingress-explicit-allow-tcp
    ├── l4-ingress-explicit-deny-any
    │   └── [Pod] l4-ingress-explicit-deny-any
    └── l4-ingress-explicit-deny-udp
        └── [Pod] l4-ingress-explicit-deny-udp
`
		podPattern, err := regexp.Compile("(?P<group>[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+)-[[:alnum:]]+-[[:alnum:]]+")
		Expect(err).NotTo(HaveOccurred())

		selfPattern, err := regexp.Compile("self-[[:alnum:]]+-[[:alnum:]]+")
		Expect(err).NotTo(HaveOccurred())

		result := runViewerSafe(Default, nil, "id", "tree", "-N=group=test")
		result = podPattern.ReplaceAll(result, []byte("${1}"))
		result = selfPattern.ReplaceAll(result, []byte("self"))
		Expect(string(result)).To(Equal(expected))
	})

	It("should handle pod selector", func() {
		expected := `k8s:io.cilium.k8s.policy.cluster: default
k8s:io.kubernetes.pod.namespace: test
k8s:group: test
k8s:io.cilium.k8s.namespace.labels.group: test
k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
k8s:io.cilium.k8s.policy.serviceaccount: default
k8s:test: self
├── [Pod] self
└── [Pod] self
`

		podPattern, err := regexp.Compile("(?P<group>[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+-[[:alnum:]]+)-[[:alnum:]]+-[[:alnum:]]+")
		Expect(err).NotTo(HaveOccurred())

		selfPattern, err := regexp.Compile("self-[[:alnum:]]+-[[:alnum:]]+")
		Expect(err).NotTo(HaveOccurred())

		result := runViewerSafe(Default, nil, "id", "tree", "-A", "-l=test=self")
		result = podPattern.ReplaceAll(result, []byte("${1}"))
		result = selfPattern.ReplaceAll(result, []byte("self"))
		Expect(string(result)).To(Equal(expected))
	})
}
