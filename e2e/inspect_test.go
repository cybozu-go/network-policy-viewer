package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testInspect() {
	cases := []struct {
		Selector  string
		ExtraArgs []string
		Expected  string
	}{
		{
			Selector: "test=self",
			Expected: `Allow,Egress,cidr:1.1.1.1/32,false,false,6,53
Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,cidr:1.1.1.1/32,false,false,132,53
Allow,Egress,cidr:8.8.8.8/32,false,false,6,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,132,53
Allow,Egress,l3-ingress-explicit-allow-all,true,true,0,0
Allow,Egress,l3-ingress-explicit-deny-all,true,true,0,0
Allow,Egress,l3-ingress-implicit-deny-all,true,true,0,0
Allow,Egress,l4-ingress-explicit-allow-any,false,false,6,53
Allow,Egress,l4-ingress-explicit-allow-any,false,false,17,53
Allow,Egress,l4-ingress-explicit-allow-any,false,false,132,53
Allow,Egress,l4-ingress-explicit-allow-tcp,false,false,6,8000
Allow,Egress,l4-ingress-explicit-deny-any,false,false,6,53
Allow,Egress,l4-ingress-explicit-deny-any,false,false,17,53
Allow,Egress,l4-ingress-explicit-deny-any,false,false,132,53
Allow,Egress,l4-ingress-explicit-deny-udp,false,false,17,161
Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0
Allow,Ingress,reserved:host,true,true,0,0
Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Deny,Egress,l3-egress-explicit-deny-all,true,true,0,0
Deny,Egress,l4-egress-explicit-deny-any,false,false,6,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,17,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,132,53
Deny,Egress,l4-egress-explicit-deny-tcp,false,false,6,8000
Deny,Ingress,cidr:192.168.100.0/24,false,false,6,8080`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidr=8.8.0.0/16"},
			Expected: `Allow,Egress,cidr:8.8.8.8/32,false,false,6,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,132,53
Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidr=8.8.0.0/16,!8.8.8.8/32"},
			Expected: `Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-private-cidrs"},
			Expected: `Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0
Deny,Ingress,cidr:192.168.100.0/24,false,false,6,8080`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-public-cidrs"},
			Expected: `Allow,Egress,cidr:1.1.1.1/32,false,false,6,53
Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,cidr:1.1.1.1/32,false,false,132,53
Allow,Egress,cidr:8.8.8.8/32,false,false,6,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,132,53
Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53`,
		},
		{
			Selector: "test=l3-ingress-explicit-allow-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Allow,Ingress,self,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-implicit-deny-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Deny,Ingress,self,true,true,0,0`,
		},
		{
			Selector: "test=l3-egress-implicit-deny-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l3-egress-explicit-deny-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-any",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Allow,Ingress,self,false,false,6,53
Allow,Ingress,self,false,false,17,53
Allow,Ingress,self,false,false,132,53`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-tcp",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Allow,Ingress,self,false,false,6,8000`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-any",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Deny,Ingress,self,false,false,6,53
Deny,Ingress,self,false,false,17,53
Deny,Ingress,self,false,false,132,53`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-udp",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Deny,Ingress,self,false,false,17,161`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-any",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-tcp",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l4-ingress-all-allow-tcp",
			Expected: `Allow,Ingress,reserved:host,false,false,6,8000
Allow,Ingress,reserved:host,true,true,0,0
Allow,Ingress,reserved:unknown,false,false,6,8000`,
		},
	}

	It("should inspect policy configuration", func() {
		for _, c := range cases {
			podName := onePodByLabelSelector(Default, "test", c.Selector)
			args := append([]string{"inspect", "-o=json", "-n=test", podName}, c.ExtraArgs...)
			result := runViewerSafe(Default, nil, args...)
			// remove hash suffix from pod names
			result = jqSafe(Default, result, "-r", `[.[] | .example = (.example | split("-") | .[0:5] | join("-"))]`)
			result = jqSafe(Default, result, "-r", `[.[] | .example = (.example | if startswith("self") then "self" else . end)]`)
			// "npv inspect" returns a unstable result, so we need to sort it in test
			result = jqSafe(Default, result, "-r", `sort_by(.policy, .direction, .example, .wildcard_protocol, .wildcard_port, .protocol, .port)`)
			result = jqSafe(Default, result, "-r", `.[] | [.policy, .direction, .example, .wildcard_protocol, .wildcard_port, .protocol, .port] | @csv`)
			resultString := strings.Replace(string(result), `"`, "", -1)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s\nargs: %v\nactual: %s\nexpected: %s", c.Selector, c.ExtraArgs, resultString, c.Expected)
		}
	})
}
