package e2e

import (
	"encoding/json"
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testJson(g Gomega, target []byte, expected string) {
	var t, e interface{}
	err := json.Unmarshal(target, &t)
	g.Expect(err).NotTo(HaveOccurred(), "actual: %s", target)

	err = json.Unmarshal([]byte(expected), &e)
	g.Expect(err).NotTo(HaveOccurred(), "expected: %s", expected)

	if !reflect.DeepEqual(t, e) {
		err := fmt.Errorf("compare failed. actual: %s, expected: %s", target, expected)
		g.Expect(err).NotTo(HaveOccurred())
	}
}

func testList() {
	cases := []struct {
		Selector string
		Expected string
	}{
		{
			Selector: "test=self",
			Expected: `[{
				"direction": "EGRESS",
				"kind": "CiliumNetworkPolicy",
				"namespace": "default",
				"name": "l3-egress"
			}]`,
		},
		{
			Selector: "test=l3-ingress-explicit-allow",
			Expected: `[{
				"direction": "INGRESS",
				"kind": "CiliumNetworkPolicy",
				"namespace": "default",
				"name": "l3-ingress-explicit-allow"
			}]`,
		},
		{
			Selector: "test=l3-ingress-no-rule",
			Expected: `[]`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny",
			Expected: `[{
				"direction": "INGRESS",
				"kind": "CiliumNetworkPolicy",
				"namespace": "default",
				"name": "l3-ingress-explicit-deny"
			}]`,
		},
	}

	It("should list applied policies", func() {
		for _, c := range cases {
			podName := onePodByLabelSelector(Default, "default", c.Selector)
			result := runViewerSafe(Default, nil, "list", podName)
			testJson(Default, result, c.Expected)
		}
	})
}
