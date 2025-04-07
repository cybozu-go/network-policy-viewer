package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testReach() {
	cases := []struct {
		Selector string
		Expected string
	}{
		{
			Selector: "test=l3-ingress-explicit-allow-all",
			Expected: `test,l3-ingress-explicit-allow-all,Ingress,Allow,true,true,0,0
test,self,Egress,Allow,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-implicit-deny-all",
			Expected: `test,self,Egress,Allow,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny-all",
			Expected: `test,l3-ingress-explicit-deny-all,Ingress,Deny,true,true,0,0
test,self,Egress,Allow,true,true,0,0`,
		},
		{
			Selector: "test=l3-egress-implicit-deny-all",
			Expected: ``,
		},
		{
			Selector: "test=l3-egress-explicit-deny-all",
			Expected: `test,self,Egress,Deny,true,true,0,0`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-any",
			Expected: `test,l4-ingress-explicit-allow-any,Ingress,Allow,false,false,6,53
test,l4-ingress-explicit-allow-any,Ingress,Allow,false,false,17,53
test,l4-ingress-explicit-allow-any,Ingress,Allow,false,false,132,53
test,self,Egress,Allow,false,false,6,53
test,self,Egress,Allow,false,false,17,53
test,self,Egress,Allow,false,false,132,53`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-tcp",
			Expected: `test,l4-ingress-explicit-allow-tcp,Ingress,Allow,false,false,6,8000
test,self,Egress,Allow,false,false,6,8000`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-any",
			Expected: `test,l4-ingress-explicit-deny-any,Ingress,Deny,false,false,6,53
test,l4-ingress-explicit-deny-any,Ingress,Deny,false,false,17,53
test,l4-ingress-explicit-deny-any,Ingress,Deny,false,false,132,53
test,self,Egress,Allow,false,false,6,53
test,self,Egress,Allow,false,false,17,53
test,self,Egress,Allow,false,false,132,53`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-udp",
			Expected: `test,l4-ingress-explicit-deny-udp,Ingress,Deny,false,false,17,161
test,self,Egress,Allow,false,false,17,161`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-any",
			Expected: `test,self,Egress,Deny,false,false,6,53
test,self,Egress,Deny,false,false,17,53
test,self,Egress,Deny,false,false,132,53`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-tcp",
			Expected: `test,self,Egress,Deny,false,false,6,8000`,
		},
		{
			Selector: "test=l4-ingress-all-allow-tcp",
			Expected: `test,l4-ingress-all-allow-tcp,Ingress,Allow,false,false,6,8000`,
		},
	}

	It("should list traffic policy", func() {
		for _, c := range cases {
			fromOption := "--from=test/" + onePodByLabelSelector(Default, "test", "test=self")
			toOption := "--to=test/" + onePodByLabelSelector(Default, "test", c.Selector)

			result := runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
			result = jqSafe(Default, result, "-r", `[.[] | .name = (.name | split("-") | .[0:5] | join("-"))]`)
			result = jqSafe(Default, result, "-r", `[.[] | .name = (.name | if startswith("self") then "self" else . end)]`)
			// "npv reach" returns a unstable result, so we need to sort it in test
			result = jqSafe(Default, result, "-r", `sort_by(.namespace, .name, .direction, .policy, .wildcard_protocol, .wildcard_port, .protocol, .port)`)
			result = jqSafe(Default, result, "-r", `.[] | [.namespace, .name, .direction, .policy, .wildcard_protocol, .wildcard_port, .protocol, .port] | @csv`)
			resultString := strings.Replace(string(result), `"`, "", -1)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s\nactual: %s\nexpected: %s", c.Selector, resultString, c.Expected)
		}
	})
}
