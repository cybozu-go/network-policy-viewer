package e2e

import (
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
})

var _ = Describe("Test network-policy-viewer", func() {
	runTest()
})

func runTest() {
	Context("dump", testDump)
	Context("list", testList)
	Context("list-manifests", testListManifests)
	Context("id-label", testIdLabel)
	Context("id-summary", testIdSummary)
	Context("inspect", testInspect)
	Context("summary", testSummary)
}
