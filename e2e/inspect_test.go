package e2e

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func formatTrafficResult(result []byte, amount bool) string {
	result = fixJsonPodField(Default, result, "example_endpoint")
	result = jqSafe(Default, result, "-r", `sort_by(.direction, .example_endpoint, .wildcard_protocol, .wildcard_port, .protocol, .port)`)
	if amount {
		result = jqSafe(Default, result, "-r", `.[] | [.example_endpoint, .bytes] | @csv`)
	} else {
		result = jqSafe(Default, result, "-r", `.[] | [.direction, .example_endpoint, .wildcard_protocol, .wildcard_port, .protocol, .port] | @csv`)
	}
	return strings.Replace(string(result), `"`, "", -1)
}

func readTraffic(result string) map[string]int {
	ret := make(map[string]int)

	scanner := bufio.NewScanner(strings.NewReader(result))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		kv := strings.Split(line, ",")
		Expect(kv).To(HaveLen(2))

		v, err := strconv.Atoi(kv[1])
		Expect(err).NotTo(HaveOccurred())

		ret[kv[0]] += v
	}
	return ret
}

func testInspect() {
	data := kubectlSafe(Default, nil, "get", "pod", "-n=test", "-l=test=self", "-o=jsonpath={.items[*].metadata.name}")
	selfNames := strings.Fields(string(data))

	cases := []struct {
		Selector  string
		ExtraArgs []string
		Expected  string
	}{
		// npv inspect should report result for each pod
		// selectors are sorted alphabetically
		{
			Selector: "test=l3-egress-explicit-deny-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l3-egress-implicit-deny-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-explicit-allow-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0
Allow,Ingress,self,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny-all",
			Expected: `Deny,Ingress,self,true,true,0,0
Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector: "test=l3-ingress-implicit-deny-all",
			Expected: `Allow,Ingress,reserved:host,true,true,0,0`,
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
Allow,Ingress,cidr:172.0.0.0/8,true,true,0,0
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
		// npv inspect should handle --with-cidrs
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidrs=0.0.0.0/0"},
			Expected: `Deny,Ingress,cidr:192.168.100.0/24,false,false,6,8080
Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0
Allow,Ingress,cidr:172.0.0.0/8,true,true,0,0
Allow,Egress,cidr:1.1.1.1/32,false,false,6,53
Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,cidr:1.1.1.1/32,false,false,132,53
Allow,Egress,cidr:8.8.8.8/32,false,false,6,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,132,53`,
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
Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0
Allow,Ingress,cidr:172.0.0.0/8,true,true,0,0`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-public-cidrs"},
			Expected: `Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Allow,Ingress,cidr:172.0.0.0/8,true,true,0,0
Allow,Egress,cidr:1.1.1.1/32,false,false,6,53
Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,cidr:1.1.1.1/32,false,false,132,53
Allow,Egress,cidr:8.8.8.8/32,false,false,6,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,132,53`,
		},
		// npv inspect should handle --mask-cidrs
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--with-cidrs=0.0.0.0/0", "--mask-cidrs"},
			Expected: `Deny,Ingress,cidr:private,false,false,6,8080
Deny,Egress,cidr:public,false,false,6,53
Deny,Egress,cidr:public,false,false,17,53
Deny,Egress,cidr:public,false,false,132,53
Allow,Ingress,cidr:private,true,true,0,0
Allow,Ingress,cidr:unknown,true,true,0,0
Allow,Egress,cidr:public,false,false,6,53
Allow,Egress,cidr:public,false,false,17,53
Allow,Egress,cidr:public,false,false,132,53`,
		},
		// npv inspect should handle reserved:unknown
		{
			Selector:  "test=l4-ingress-all-allow-tcp",
			ExtraArgs: []string{"--with-cidrs=0.0.0.0/0"},
			Expected:  `Allow,Ingress,reserved:unknown,false,false,6,8000`,
		},
		{
			Selector:  "test=l4-ingress-all-allow-tcp",
			ExtraArgs: []string{"--with-cidrs=10.0.0.0/8"},
			Expected:  `Allow,Ingress,reserved:unknown,false,false,6,8000`,
		},
		{
			Selector:  "test=l4-ingress-all-allow-tcp",
			ExtraArgs: []string{"--with-public-cidrs"},
			Expected:  `Allow,Ingress,reserved:unknown,false,false,6,8000`,
		},
		{
			Selector:  "test=l4-ingress-all-allow-tcp",
			ExtraArgs: []string{"--with-private-cidrs"},
			Expected:  `Allow,Ingress,reserved:unknown,false,false,6,8000`,
		},
		// npv inspect should handle --used
		{
			Selector:  "test=l3-ingress-explicit-allow-all",
			ExtraArgs: []string{"--used"},
			Expected:  `Allow,Ingress,self,true,true,0,0`,
		},
		{
			Selector:  "test=l4-ingress-explicit-allow-tcp",
			ExtraArgs: []string{"--used"},
			Expected:  `Allow,Ingress,self,false,false,6,8000`,
		},
		// npv inspect should handle --unused
		{
			Selector:  "test=l4-ingress-explicit-deny-udp",
			ExtraArgs: []string{"--denied", "--unused"},
			Expected:  `Deny,Ingress,self,false,false,17,161`,
		},
		// npv inspect should handle --used without pod name
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
		// npv inspect should handle --ingress and --egress
		// npv inspect should handle --allowed and --denied
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--ingress", "--allowed"},
			Expected: `Allow,Ingress,cidr:10.100.0.0/16,true,true,0,0
Allow,Ingress,cidr:172.0.0.0/8,true,true,0,0
Allow,Ingress,reserved:host,true,true,0,0`,
		},
		{
			Selector:  "test=self",
			ExtraArgs: []string{"--egress", "--denied"},
			Expected: `Deny,Egress,cidr:8.8.4.4/32,false,false,6,53
Deny,Egress,cidr:8.8.4.4/32,false,false,17,53
Deny,Egress,cidr:8.8.4.4/32,false,false,132,53
Deny,Egress,l3-egress-explicit-deny-all,true,true,0,0
Deny,Egress,l4-egress-explicit-deny-any,false,false,6,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,17,53
Deny,Egress,l4-egress-explicit-deny-any,false,false,132,53
Deny,Egress,l4-egress-explicit-deny-tcp,false,false,6,8000`,
		},
		// npv inspect should handle --group ns (TBD)
		// npv inspect should handle --group all
		{
			ExtraArgs: []string{selfNames[0], "--used"},
			Expected: `Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,l3-ingress-explicit-allow-all,true,true,0,0
Allow,Egress,l4-ingress-explicit-allow-tcp,false,false,6,8000`,
		},
		{
			ExtraArgs: []string{selfNames[1], "--used"},
			Expected: `Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,l3-ingress-explicit-allow-all,true,true,0,0
Allow,Egress,l4-ingress-explicit-allow-tcp,false,false,6,8000`,
		},
		{
			ExtraArgs: []string{"-l=test=self", "--used", "--group=all"},
			Expected: `Allow,Egress,cidr:1.1.1.1/32,false,false,17,53
Allow,Egress,cidr:8.8.8.8/32,false,false,17,53
Allow,Egress,l3-ingress-explicit-allow-all,true,true,0,0
Allow,Egress,l4-ingress-explicit-allow-tcp,false,false,6,8000`,
		},
	}

	It("should inspect policy configuration", func() {
		for _, c := range cases {
			By(fmt.Sprintf("inspecting %v %v", c.Selector, c.ExtraArgs))
			args := []string{"inspect", "-o=json", "-n=test"}
			if c.Selector != "" {
				podName := onePodByLabelSelector(Default, "test", c.Selector)
				args = append(args, podName)
			}
			args = append(args, c.ExtraArgs...)
			result := runViewerSafe(Default, nil, args...)
			result = fixJsonPodField(Default, result, "example_endpoint")
			result = jqSafe(Default, result, "-r", `.[] | [.policy, .direction, .example_endpoint, .wildcard_protocol, .wildcard_port, .protocol, .port] | @csv`)
			resultString := strings.Replace(string(result), `"`, "", -1)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s\nargs: %v\nactual: %s\nexpected: %s", c.Selector, c.ExtraArgs, resultString, c.Expected)
		}
	})

	It("should show combined traffic amount", func() {
		// Run npv inspect --used -ga for two self pods separately
		result := runViewerSafe(Default, nil, "inspect", "--used", "-ga", "-o=json", "-n=test", selfNames[0])
		result1 := formatTrafficResult(result, true)

		result = runViewerSafe(Default, nil, "inspect", "--used", "-ga", "-o=json", "-n=test", selfNames[1])
		result2 := formatTrafficResult(result, true)
		amount12 := readTraffic(result1 + "\n" + result2)

		// Run npv inspect --used -ga for two self pods with a label selector
		result = runViewerSafe(Default, nil, "inspect", "--used", "-ga", "-o=json", "-n=test", "-l=test=self")
		result3 := formatTrafficResult(result, true)
		amount3 := readTraffic(result3)

		// Check
		Expect(amount12).To(Equal(amount3))
	})
}
