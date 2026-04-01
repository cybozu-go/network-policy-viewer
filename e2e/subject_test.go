package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testSubject() {
	data := kubectlSafe(Default, nil, "get", "pod", "-n=test", "-l=test=self", "-o=jsonpath={.items[*].metadata.name}")
	selfNames := strings.Fields(string(data))

	cases := []struct {
		Args     []string
		Expected string
	}{
		// Test --group //
		// npv subject --group=all should not show individual subject
		{
			Args:     []string{"-A", "--group=all"},
			Expected: ``,
		},
		// npv subject --group=ns should display subjects as NS
		{
			Args: []string{"-A", "--group=ns"},
			Expected: `cilium-agent-proxy
default
kube-system
local-path-storage
test
test-l3
test-l4`,
		},
		// npv subject --group=pod should display subjects as POD when a single namespace is selected
		{
			Args:     []string{"-n=test", "-l=test=self", "--group=pod"},
			Expected: strings.Join(selfNames, "\n"),
		},
		// npv subject --group=pod should display subjects as NS/POD when multiple namespaces are selected
		{
			Args:     []string{"-A", "-l=test=self", "--group=pod"},
			Expected: fmt.Sprintf("test/%s\ntest/%s", selfNames[0], selfNames[1]),
		},
		// Test selector options //
		// npv subject -A should select subjects from all namespaces (already tested)
		// npv subject -N should select subjects from the selected namespaces
		{
			Args: []string{"-N=group=test", "--group=ns"},
			Expected: `test
test-l3
test-l4`,
		},
		// npv subject -l should select pods with the specified label (already tested)
		// npv subject --node should select pods on the node from all namespaces
		{
			Args:     []string{"--node=kind-worker", "-l=app.kubernetes.io/name=cilium-agent-proxy", "--group=ns"},
			Expected: `cilium-agent-proxy`,
		},
	}

	It("should show subjects", func() {
		for _, c := range cases {
			By(fmt.Sprintf("checking %v", c.Args))
			args := append([]string{"subject"}, c.Args...)
			result := strings.TrimSpace(string(runViewerSafe(Default, nil, args...)))
			Expect(result).To(Equal(c.Expected), "compare failed. actual: %s\nexpected: %s", result, c.Expected)
		}
	})

	It("should handle --node", func() {
		expected := strings.TrimSpace(string(kubectlSafe(Default, nil, "get", "pod", "-n=cilium-agent-proxy", "--field-selector=spec.nodeName=kind-worker", "-oname")))
		expected = strings.ReplaceAll(expected, "pod/", "cilium-agent-proxy/")

		actual := strings.TrimSpace(string(runViewerSafe(Default, nil, "subject", "--node=kind-worker", "-l=app.kubernetes.io/name=cilium-agent-proxy")))
		Expect(actual).To(Equal(expected))
	})
}
