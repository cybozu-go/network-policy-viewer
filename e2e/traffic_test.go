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
	// remove hash suffix from pod names
	result = jqSafe(Default, result, "-r", `[.[] | .example = (.example | split("-") | .[0:5] | join("-"))]`)
	result = jqSafe(Default, result, "-r", `[.[] | .example = (.example | if startswith("self") then "self" else . end)]`)
	result = jqSafe(Default, result, "-r", `sort_by(.direction, .cidr, .example, .wildcard_protocol, .wildcard_port, .protocol, .port)`)
	if amount {
		result = jqSafe(Default, result, "-r", `.[] | [.example, .bytes] | @csv`)
	} else {
		result = jqSafe(Default, result, "-r", `.[] | [.direction, .cidr, .example, .wildcard_protocol, .wildcard_port, .protocol, .port] | @csv`)
	}
	return strings.Replace(string(result), `"`, "", -1)
}

func readTraffic(result string) map[string]int {
	ret := make(map[string]int)

	scanner := bufio.NewScanner(strings.NewReader(result))
	for scanner.Scan() {
		line := scanner.Text()
		kv := strings.Split(line, ",")
		Expect(kv).To(HaveLen(2))

		v, err := strconv.Atoi(kv[1])
		Expect(err).NotTo(HaveOccurred())

		ret[kv[0]] += v
	}
	return ret
}

func testTraffic() {
	It("should show all active routes", func() {
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

		cases := []struct {
			Selector string
			Expected string
		}{
			{
				Selector: l3PodName,
				Expected: `Ingress,,self,true,true,0,0`,
			},
			{
				Selector: l4PodName,
				Expected: `Ingress,,self,false,false,6,8000`,
			},
			{
				Selector: selfNames[0],
				Expected: `Egress,,l3-ingress-explicit-allow-all,true,true,0,0
Egress,,l4-ingress-explicit-allow-tcp,false,false,6,8000
Egress,1.1.1.1/32,cidr:1.1.1.1/32,false,false,17,53`,
			},
			{
				Selector: selfNames[1],
				Expected: `Egress,,l3-ingress-explicit-allow-all,true,true,0,0
Egress,,l4-ingress-explicit-allow-tcp,false,false,6,8000
Egress,8.8.8.8/32,cidr:8.8.8.8/32,false,false,17,53`,
			},
			{
				Selector: "-l=test=self",
				Expected: `Egress,,l3-ingress-explicit-allow-all,true,true,0,0
Egress,,l4-ingress-explicit-allow-tcp,false,false,6,8000
Egress,1.1.1.1/32,cidr:1.1.1.1/32,false,false,17,53
Egress,8.8.8.8/32,cidr:8.8.8.8/32,false,false,17,53`,
			},
		}
		for _, c := range cases {
			result := runViewerSafe(Default, nil, "traffic", "-o=json", "-n=test", c.Selector)
			resultString := formatTrafficResult(result, false)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s\nactual: %s\nexpected: %s", c.Selector, resultString, c.Expected)
		}

		By("checking npv traffic -l shows combined traffic amount")
		result := runViewerSafe(Default, nil, "traffic", "-o=json", "-n=test", selfNames[0])
		result1 := formatTrafficResult(result, true)

		result = runViewerSafe(Default, nil, "traffic", "-o=json", "-n=test", selfNames[1])
		result2 := formatTrafficResult(result, true)
		amount12 := readTraffic(result1 + "\n" + result2)

		result = runViewerSafe(Default, nil, "traffic", "-o=json", "-n=test", "-l=test=self")
		result3 := formatTrafficResult(result, true)
		amount3 := readTraffic(result3)
		Expect(amount12).To(Equal(amount3))
	})
}
