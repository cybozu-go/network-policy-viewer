package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testAgentNode() {
	It("should show agent for nodes", func() {
		data := kubectlSafe(Default, nil, "get", "node", "-o=jsonpath={.items[*].metadata.name}")
		nodes := strings.Fields(string(data))

		for _, node := range nodes {
			expected := string(kubectlSafe(Default, nil, "get", "pod", "-n=kube-system", "-l=k8s-app=cilium", "--field-selector=spec.nodeName="+node, "-o=jsonpath={.items[*].metadata.name}"))
			expected = strings.TrimSpace(expected)
			actual := string(runViewerSafe(Default, nil, "agent", "node", node))
			actual = strings.TrimSpace(actual)
			Expect(actual).To(Equal(expected))
		}
	})
}

func testAgentPod() {
	It("should show agent for pods", func() {
		data := kubectlSafe(Default, nil, "get", "pod", "-n=test", "-o=jsonpath={.items[*].metadata.name}")
		pods := strings.Fields(string(data))

		for _, pod := range pods {
			node := string(kubectlSafe(Default, nil, "get", "pod", "-n=test", pod, "-o=jsonpath={.spec.nodeName}"))
			node = strings.TrimSpace(node)

			expected := string(kubectlSafe(Default, nil, "get", "pod", "-n=kube-system", "-l=k8s-app=cilium", "--field-selector=spec.nodeName="+node, "-o=jsonpath={.items[*].metadata.name}"))
			expected = strings.TrimSpace(expected)
			actual := string(runViewerSafe(Default, nil, "agent", "pod", "-n=test", pod))
			actual = strings.TrimSpace(actual)
			Expect(actual).To(Equal(expected), "failed to show agent for pod %s", pod)
		}
	})
}
