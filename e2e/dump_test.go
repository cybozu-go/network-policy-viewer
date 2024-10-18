package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testDump() {
	It("should dump endpoint content", func() {
		podName := onePodByLabelSelector(Default, "test", "test=self")
		ret := runViewerSafe(Default, nil, "dump", "-n=test", podName)
		state := jqSafe(Default, ret, "-r", ".status.state")
		Expect(string(state)).To(Equal("ready"))
	})
}
