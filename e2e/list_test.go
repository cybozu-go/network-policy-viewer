package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testList() {
	cases := []struct {
		Selector string
		Expected string
	}{
		{
			Selector: "test=self",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Egress,CiliumNetworkPolicy,test,l3-egress
Egress,CiliumNetworkPolicy,test,l4-egress
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline`,
		},
		{
			Selector: "test=l3-ingress-explicit-allow-all",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumNetworkPolicy,test,l3-ingress-explicit-allow-all`,
		},
		{
			Selector: "test=l3-ingress-implicit-deny-all",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline`,
		},
		{
			Selector: "test=l3-ingress-explicit-deny-all",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumNetworkPolicy,test,l3-ingress-explicit-deny-all`,
		},
		{
			Selector: "test=l3-egress-implicit-deny-all",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline`,
		},
		{
			Selector: "test=l3-egress-explicit-deny-all",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-any",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumNetworkPolicy,test,l4-ingress-explicit-allow-any`,
		},
		{
			Selector: "test=l4-ingress-explicit-allow-tcp",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumNetworkPolicy,test,l4-ingress-explicit-allow-tcp`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-any",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumNetworkPolicy,test,l4-ingress-explicit-deny-any`,
		},
		{
			Selector: "test=l4-ingress-explicit-deny-udp",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumNetworkPolicy,test,l4-ingress-explicit-deny-udp`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-any",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline`,
		},
		{
			Selector: "test=l4-egress-explicit-deny-tcp",
			Expected: `Egress,CiliumClusterwideNetworkPolicy,-,l3-baseline
Ingress,CiliumClusterwideNetworkPolicy,-,l3-baseline`,
		},
	}

	It("should list applied policies", func() {
		for _, c := range cases {
			podName := onePodByLabelSelector(Default, "test", c.Selector)
			result := runViewerSafe(Default, nil, "list", "-o=json", "-n=test", podName)
			result = jqSafe(Default, result, "-r", ".[] | [.direction, .kind, .namespace, .name] | @csv")
			resultString := strings.Replace(string(result), `"`, "", -1)
			Expect(resultString).To(Equal(c.Expected), "compare failed. selector: %s\nactual: %s\nexpected: %s", c.Selector, resultString, c.Expected)
		}
	})
}

func testListManifests() {
	expected := `apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  annotations: {}
  name: l3-baseline
spec:
  egressDeny:
  - toEndpoints:
    - matchLabels:
        k8s:test: scapegoat
  endpointSelector:
    matchLabels:
      k8s:group: test
  ingressDeny:
  - fromEndpoints:
    - matchLabels:
        k8s:test: scapegoat
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  annotations: {}
  name: l3-egress
  namespace: test
spec:
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:test: l3-ingress-explicit-allow-all
  - toEndpoints:
    - matchLabels:
        k8s:test: l3-ingress-no-rule
  - toEndpoints:
    - matchLabels:
        k8s:test: l3-ingress-implicit-deny-all
  - toEndpoints:
    - matchLabels:
        k8s:test: l3-ingress-explicit-deny-all
  egressDeny:
  - toEndpoints:
    - matchLabels:
        k8s:test: l3-egress-explicit-deny-all
  endpointSelector:
    matchLabels:
      k8s:test: self
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  annotations: {}
  name: l4-egress
  namespace: test
spec:
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:test: l4-ingress-explicit-allow-any
    toPorts:
    - ports:
      - port: "53"
  - toEndpoints:
    - matchLabels:
        k8s:test: l4-ingress-explicit-allow-tcp
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
  - toEndpoints:
    - matchLabels:
        k8s:test: l4-ingress-explicit-deny-any
    toPorts:
    - ports:
      - port: "53"
  - toEndpoints:
    - matchLabels:
        k8s:test: l4-ingress-explicit-deny-udp
    toPorts:
    - ports:
      - port: "161"
        protocol: UDP
  - toCIDR:
    - 8.8.8.8/32
    toPorts:
    - ports:
      - port: "53"
  egressDeny:
  - toEndpoints:
    - matchLabels:
        k8s:test: l4-egress-explicit-deny-any
    toPorts:
    - ports:
      - port: "53"
  - toEndpoints:
    - matchLabels:
        k8s:test: l4-egress-explicit-deny-tcp
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
  - toCIDR:
    - 8.8.4.4/32
    toPorts:
    - ports:
      - port: "53"
  endpointSelector:
    matchLabels:
      k8s:test: self`

	It("should list applied policy manifests", func() {
		podName := onePodByLabelSelector(Default, "test", "test=self")
		result := strings.TrimSpace(string(runViewerSafe(Default, nil, "list", "-n=test", "-m", podName)))
		Expect(result).To(Equal(expected), "compare failed.\nactual: %s\nexpected: %s", result, expected)
	})
}
