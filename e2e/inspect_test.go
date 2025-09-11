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
			Expected: `Deny,Ingress,cidr:192.168.100.0/24,false,false,6,8080
Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Deny,Egress,l3-egress-explicit-deny-all,true,true,0,0
Deny,Egress,l4-egress-explicit-deny-any,false,false,6,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,17,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,132,53
Deny,Egress,l4-egress-explicit-deny-tcp,false,false,6,8000
Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0
Allow,Ingress,reserved:host,true,true,0,0
Allow,Egress,cidr:1.1.1.1/32,false,false,6,53
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
Allow,Egress,l4-ingress-explicit-deny-udp,false,false,17,161`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidrs=8.8.0.0/16"},
			Expected: `Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Allow,Egress,cidr:8.8.8.8/32,false,false,6,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,132,53`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidrs=8.8.0.0/16,!8.8.8.8/32"},
			Expected: `Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidrs=10.100.0.0/12,!10.100.0.0/16"},
			Expected:  ``,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidrs=10.100.0.0/12,!10.100.0.0/20"},
			Expected:  `Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidrs=10.100.0.0/16,!10.100.0.0/16"},
			Expected:  ``,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-private-cidrs"},
			Expected: `Deny,Ingress,cidr:192.168.100.0/24,false,false,6,8080
Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-public-cidrs"},
			Expected: `Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Allow,Egress,cidr:1.1.1.1/32,false,false,6,53
Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,cidr:1.1.1.1/32,false,false,132,53
Allow,Egress,cidr:8.8.8.8/32,false,false,6,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,132,53`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--allowed", "--ingress"},
			Expected: `Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0
Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--denied", "--egress"},
			Expected: `Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Deny,Egress,l3-egress-explicit-deny-all,true,true,0,0
Deny,Egress,l4-egress-explicit-deny-any,false,false,6,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,17,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,132,53
Deny,Egress,l4-egress-explicit-deny-tcp,false,false,6,8000`,
		},
		{
			Selector:  "test=l4-ingress-explicit-allow-tcp",
			ExtraArgs: []string{"--used"},
			Expected:  `Allow,Ingress,self,false,false,6,8000`,
		},
		{
			Selector:  "test=l4-ingress-explicit-deny-udp",
			ExtraArgs: []string{"--denied", "--unused"},
			Expected:  `Deny,Ingress,self,false,false,17,161`,
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
			Expected: `Deny,Ingress,self,true,true,0,0
Allow,Ingress,reserved:host,true,true,0,0`,
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
			Expected: `Deny,Ingress,self,false,false,6,53
Deny,Ingress,self,false,false,17,53
Deny,Ingress,self,false,false,132,53
Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-udp",
			Expected: `Deny,Ingress,self,false,false,17,161
Allow,Ingress,reserved:host,true,true,0,0`,
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
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Allow,Ingress,reserved:host,false,false,6,8000
Allow,Ingress,reserved:unknown,false,false,6,8000`,
		},
		{
			Selector:  "test=l4-ingress-all-allow-tcp",
			ExtraArgs: []string{"--with-cidrs=0.0.0.0/0"},
			Expected:  `Allow,Ingress,reserved:unknown,false,false,6,8000`,
		},
		{
			ExtraArgs: []string{"--used"},
			Expected: `Allow,Ingress,self,true,true,0,0
Allow,Ingress,self,false,false,6,8000
Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,l3-ingress-explicit-allow-all,true,true,0,0
Allow,Egress,l4-ingress-explicit-allow-tcp,false,false,6,8000
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,l3-ingress-explicit-allow-all,true,true,0,0
Allow,Egress,l4-ingress-explicit-allow-tcp,false,false,6,8000`,
		},
	}

	It("should inspect policy configuration", func() {
		for _, c := range cases {
			args := []string{"inspect", "-o=json", "-n=test"}
			if c.Selector != "" {
				podName := onePodByLabelSelector(Default, "test", c.Selector)
				args = append(args, podName)
			}
			args = append(args, c.ExtraArgs...)
			result := runViewerSafe(Default, nil, args...)
			// remove hash suffix from pod names
			result = jqSafe(Default, result, "-r", `[.[] | .example_endpoint = (.example_endpoint | split("-") | .[0:5] | join("-"))]`)
			result = jqSafe(Default, result, "-r", `[.[] | .example_endpoint = (.example_endpoint | if startswith("self") then "self" else . end)]`)
			result = jqSafe(Default, result, "-r", `.[] | [.policy, .direction, .example_endpoint, .wildcard_protocol, .wildcard_port, .protocol, .port] | @csv`)
			resultString := strings.Replace(string(result), `"`, "", -1)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s\nargs: %v\nactual: %s\nexpected: %s", c.Selector, c.ExtraArgs, resultString, c.Expected)
		}
	})
}
