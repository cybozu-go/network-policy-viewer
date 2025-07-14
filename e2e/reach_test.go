package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func formatReachResult(result []byte) string {
	// remove hash suffix from pod names
	result = jqSafe(Default, result, "-r", `[.[] | .example_endpoint = (.example_endpoint | split("-") | .[0:5] | join("-"))]`)
	result = jqSafe(Default, result, "-r", `[.[] | .example_endpoint = (.example_endpoint | if startswith("self") then "self" else . end)]`)
	// "npv reach" returns a unstable result, so we need to sort it in test
	result = jqSafe(Default, result, "-r", `sort_by(.role, .direction, .policy, .example_endpoint, .wildcard_protocol, .wildcard_port, .protocol, .port)`)
	result = jqSafe(Default, result, "-r", `.[] | [.role, .direction, .policy, .example_endpoint, .wildcard_protocol, .wildcard_port, .protocol, .port] | @csv`)
	return strings.Replace(string(result), `"`, "", -1)
}

func testReach() {
	cases := []struct {
		Selector string
		Expected string
	}{
		{
			Selector: "test=l3-ingress-explicit-allow-all",
			Expected: `Receiver,Ingress,Allow,self,true,true,0,0
Sender,Egress,Allow,l3-ingress-explicit-allow-all,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-implicit-deny-all",
			Expected: `Sender,Egress,Allow,l3-ingress-implicit-deny-all,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny-all",
			Expected: `Receiver,Ingress,Deny,self,true,true,0,0
Sender,Egress,Allow,l3-ingress-explicit-deny-all,true,true,0,0`,
		},
		{
			Selector: "test=l3-egress-implicit-deny-all",
			Expected: ``,
		},
		{
			Selector: "test=l3-egress-explicit-deny-all",
			Expected: `Sender,Egress,Deny,l3-egress-explicit-deny-all,true,true,0,0`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-any",
			Expected: `Receiver,Ingress,Allow,self,false,false,6,53
Receiver,Ingress,Allow,self,false,false,17,53
Receiver,Ingress,Allow,self,false,false,132,53
Sender,Egress,Allow,l4-ingress-explicit-allow-any,false,false,6,53
Sender,Egress,Allow,l4-ingress-explicit-allow-any,false,false,17,53
Sender,Egress,Allow,l4-ingress-explicit-allow-any,false,false,132,53`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-tcp",
			Expected: `Receiver,Ingress,Allow,self,false,false,6,8000
Sender,Egress,Allow,l4-ingress-explicit-allow-tcp,false,false,6,8000`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-any",
			Expected: `Receiver,Ingress,Deny,self,false,false,6,53
Receiver,Ingress,Deny,self,false,false,17,53
Receiver,Ingress,Deny,self,false,false,132,53
Sender,Egress,Allow,l4-ingress-explicit-deny-any,false,false,6,53
Sender,Egress,Allow,l4-ingress-explicit-deny-any,false,false,17,53
Sender,Egress,Allow,l4-ingress-explicit-deny-any,false,false,132,53`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-udp",
			Expected: `Receiver,Ingress,Deny,self,false,false,17,161
Sender,Egress,Allow,l4-ingress-explicit-deny-udp,false,false,17,161`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-any",
			Expected: `Sender,Egress,Deny,l4-egress-explicit-deny-any,false,false,6,53
Sender,Egress,Deny,l4-egress-explicit-deny-any,false,false,17,53
Sender,Egress,Deny,l4-egress-explicit-deny-any,false,false,132,53`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-tcp",
			Expected: `Sender,Egress,Deny,l4-egress-explicit-deny-tcp,false,false,6,8000`,
		},
		{
			Selector: "test=l4-ingress-all-allow-tcp",
			Expected: `Receiver,Ingress,Allow,reserved:unknown,false,false,6,8000`,
		},
	}

	It("should list traffic policy", func() {
		for _, c := range cases {
			fromOption := "--from=test/" + onePodByLabelSelector(Default, "test", "test=self")
			toOption := "--to=test/" + onePodByLabelSelector(Default, "test", c.Selector)

			result := runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
			resultString := formatReachResult(result)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s\nactual: %s\nexpected: %s", c.Selector, resultString, c.Expected)
		}
	})
}

func testReachCIDR() {
	expectedIngressPrivate := `Receiver,Ingress,Allow,cidr:10.100.0.0/16,true,true,0,0
Receiver,Ingress,Deny,cidr:192.168.100.0/24,false,false,6,8080`
	expectedIngressPublic := ""
	expectedEgressPrivate := ""
	expectedEgressPublic := `Sender,Egress,Allow,cidr:1.1.1.1/32,false,false,6,53
Sender,Egress,Allow,cidr:1.1.1.1/32,false,false,17,53
Sender,Egress,Allow,cidr:1.1.1.1/32,false,false,132,53
Sender,Egress,Allow,cidr:8.8.8.8/32,false,false,6,53
Sender,Egress,Allow,cidr:8.8.8.8/32,false,false,17,53
Sender,Egress,Allow,cidr:8.8.8.8/32,false,false,132,53
Sender,Egress,Deny,cidr:8.8.4.4/32,false,false,6,53
Sender,Egress,Deny,cidr:8.8.4.4/32,false,false,17,53
Sender,Egress,Deny,cidr:8.8.4.4/32,false,false,132,53`

	It("should list ingress traffic policy using --from-cidrs", func() {
		fromOption := "--from-cidrs=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
		toOption := "--to=test/" + onePodByLabelSelector(Default, "test", "test=self")

		result := runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
		resultString := formatReachResult(result)
		Expect(resultString).To(Equal(expectedIngressPrivate), "compare failed. actual: %s\nexpected: %s", resultString, expectedIngressPrivate)

		// Retry with sugar syntax
		fromOption = "--from-private-cidrs"
		result = runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
		resultString = formatReachResult(result)
		Expect(resultString).To(Equal(expectedIngressPrivate), "compare failed. actual: %s\nexpected: %s", resultString, expectedIngressPrivate)

		// Another test
		fromOption = "--from-public-cidrs"
		result = runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
		resultString = formatReachResult(result)
		Expect(resultString).To(Equal(expectedIngressPublic), "compare failed. actual: %s\nexpected: %s", resultString, expectedIngressPublic)
	})

	It("should list egress traffic policy using --to-cidrs", func() {
		fromOption := "--from=test/" + onePodByLabelSelector(Default, "test", "test=self")
		toOption := "--to-cidrs=0.0.0.0/0,!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16"

		result := runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
		resultString := formatReachResult(result)
		Expect(resultString).To(Equal(expectedEgressPublic), "compare failed. actual: %s\nexpected: %s", resultString, expectedEgressPublic)

		// Retry with sugar syntax
		toOption = "--to-public-cidrs"
		result = runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
		resultString = formatReachResult(result)
		Expect(resultString).To(Equal(expectedEgressPublic), "compare failed. actual: %s\nexpected: %s", resultString, expectedEgressPublic)

		// Another test
		toOption = "--to-private-cidrs"
		result = runViewerSafe(Default, nil, "reach", "-o=json", fromOption, toOption)
		resultString = formatReachResult(result)
		Expect(resultString).To(Equal(expectedEgressPrivate), "compare failed. actual: %s\nexpected: %s", resultString, expectedEgressPrivate)
	})
}
