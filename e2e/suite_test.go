package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func Test(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Test")
}

var _ = BeforeSuite(func() {
	SetDefaultEventuallyPollingInterval(time.Second)
	SetDefaultEventuallyTimeout(5 * time.Minute)

	processTestTraffic()
})

var _ = Describe("Test network-policy-viewer", func() {
	runTest()
})

func processTestTraffic() {
	data := kubectlSafe(Default, nil, "get", "pod", "-n=test", "-l=test=self", "-o=jsonpath={.items[*].metadata.name}")
	selfNames := strings.Fields(string(data))
	l3PodName := onePodByLabelSelector(Default, "test", "test=l3-ingress-explicit-allow-all")
	l4PodName := onePodByLabelSelector(Default, "test", "test=l4-ingress-explicit-allow-tcp")
	l3PodIP := string(kubectlSafe(Default, nil, "get", "pod", "-n=test", l3PodName, "-o=jsonpath={.status.podIP}"))
	l4PodIP := string(kubectlSafe(Default, nil, "get", "pod", "-n=test", l4PodName, "-o=jsonpath={.status.podIP}"))

	kubectlSafe(Default, nil, "exec", "-n=test", selfNames[0], "--", "dig", "@1.1.1.1", "google.com")
	kubectlSafe(Default, nil, "exec", "-n=test", selfNames[1], "--", "dig", "@8.8.8.8", "google.com")
	for _, p := range selfNames {
		kubectlSafe(Default, nil, "exec", "-n=test", p, "--", "curl", fmt.Sprintf("http://%s:8000", l3PodIP))
		kubectlSafe(Default, nil, "exec", "-n=test", p, "--", "curl", fmt.Sprintf("http://%s:8000", l4PodIP))
	}
}

func runTest() {
	Context("agent-node", testAgentNode)
	Context("agent-pod", testAgentPod)
	Context("dump", testDump)
	Context("list", testList)
	Context("list-with-selector", testListWithSelector)
	Context("list-manifests", testListManifests)
	Context("id-label", testIdLabel)
	Context("id-summary", testIdSummary)
	Context("id-tree", testIdTree)
	Context("inspect", testInspect)
	Context("summary", testSummary)
	Context("summary-all", testSummaryAll)
	Context("summary-node", testSummaryNode)
	Context("manifest-generate", testManifestGenerate)
	Context("manifest-range", testManifestRange)
	Context("reach", testReach)
	Context("reach-cidr", testReachCIDR)
	Context("traffic", testTraffic)
}
