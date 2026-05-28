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
		{
			Args:     []string{"-A", "--group=all"},
			Expected: ``,
		},
		{
			Args: []string{"-A", "--group=ns"},
			Expected: `cilium-agent-proxy
default
kube-system
local-path-storage
test`,
		},
		// npv subject POD should echo its name
		{
			Args:     []string{"-n=test", selfNames[0]},
			Expected: selfNames[0],
		},
		// npv subject -n -gn should display subjects as NS
		{
			Args:     []string{"-n=test", "-l=test=self", "--group=ns"},
			Expected: `test`,
		},
		// npv subject -A -gp should display subjects as NS/POD
		{
			Args:     []string{"-A", "-l=test=self", "--group=pod"},
			Expected: fmt.Sprintf("test/%s\ntest/%s", selfNames[0], selfNames[1]),
		},
		// npv subject -n -gp should display subjects as POD
		{
			Args:     []string{"-n=test", "-l=test=self", "--group=pod"},
			Expected: strings.Join(selfNames, "\n"),
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
