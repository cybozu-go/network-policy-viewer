package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testLookup() {
	cases := []struct {
		Namespace string
		Selector  string
		Expected  string
	}{
		{
			Namespace: "test",
			Selector:  "test=self",
			Expected: `self,CiliumClusterwideNetworkPolicy,-,l3-baseline
self,CiliumNetworkPolicy,test,l3-self
self,CiliumNetworkPolicy,test,l4-self
self,CiliumNetworkPolicy,test-l3,l3-ingress-explicit-allow-all
self,CiliumNetworkPolicy,test-l3,l3-ingress-explicit-deny-all
self,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-allow-any
self,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-allow-tcp
self,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-deny-any
self,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-deny-udp`,
		},
		{
			Namespace: "test-l3",
			Selector:  "test=l3-ingress-explicit-allow-all",
			Expected: `l3-ingress-explicit-allow-all,CiliumClusterwideNetworkPolicy,-,l3-baseline
l3-ingress-explicit-allow-all,CiliumNetworkPolicy,test,l3-self
l3-ingress-explicit-allow-all,CiliumNetworkPolicy,test-l3,l3-ingress-explicit-allow-all`,
		},
		{
			Namespace: "test-l3",
			Selector:  "test=l3-ingress-implicit-deny-all",
			Expected: `l3-ingress-implicit-deny-all,CiliumClusterwideNetworkPolicy,-,l3-baseline
l3-ingress-implicit-deny-all,CiliumNetworkPolicy,test,l3-self`,
		},
		{
			Namespace: "test-l3",
			Selector:  "test=l3-ingress-explicit-deny-all",
			Expected: `l3-ingress-explicit-deny-all,CiliumClusterwideNetworkPolicy,-,l3-baseline
l3-ingress-explicit-deny-all,CiliumNetworkPolicy,test,l3-self
l3-ingress-explicit-deny-all,CiliumNetworkPolicy,test-l3,l3-ingress-explicit-deny-all`,
		},
		{
			Namespace: "test-l3",
			Selector:  "test=l3-egress-implicit-deny-all",
			Expected:  `l3-egress-implicit-deny-all,CiliumClusterwideNetworkPolicy,-,l3-baseline`,
		},
		{
			Namespace: "test-l3",
			Selector:  "test=l3-egress-explicit-deny-all",
			Expected: `l3-egress-explicit-deny-all,CiliumClusterwideNetworkPolicy,-,l3-baseline
l3-egress-explicit-deny-all,CiliumNetworkPolicy,test,l3-self`,
		},
		{
			Namespace: "test-l4",
			Selector:  "test=l4-ingress-explicit-allow-any",
			Expected: `l4-ingress-explicit-allow-any,CiliumClusterwideNetworkPolicy,-,l3-baseline
l4-ingress-explicit-allow-any,CiliumNetworkPolicy,test,l4-self
l4-ingress-explicit-allow-any,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-allow-any`,
		},
		{
			Namespace: "test-l4",
			Selector:  "test=l4-ingress-explicit-allow-tcp",
			Expected: `l4-ingress-explicit-allow-tcp,CiliumClusterwideNetworkPolicy,-,l3-baseline
l4-ingress-explicit-allow-tcp,CiliumNetworkPolicy,test,l4-self
l4-ingress-explicit-allow-tcp,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-allow-tcp`,
		},
		{
			Namespace: "test-l4",
			Selector:  "test=l4-ingress-explicit-deny-any",
			Expected: `l4-ingress-explicit-deny-any,CiliumClusterwideNetworkPolicy,-,l3-baseline
l4-ingress-explicit-deny-any,CiliumNetworkPolicy,test,l4-self
l4-ingress-explicit-deny-any,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-deny-any`,
		},
		{
			Namespace: "test-l4",
			Selector:  "test=l4-ingress-explicit-deny-udp",
			Expected: `l4-ingress-explicit-deny-udp,CiliumClusterwideNetworkPolicy,-,l3-baseline
l4-ingress-explicit-deny-udp,CiliumNetworkPolicy,test,l4-self
l4-ingress-explicit-deny-udp,CiliumNetworkPolicy,test-l4,l4-ingress-explicit-deny-udp`,
		},
		{
			Namespace: "test-l4",
			Selector:  "test=l4-egress-explicit-deny-any",
			Expected: `l4-egress-explicit-deny-any,CiliumClusterwideNetworkPolicy,-,l3-baseline
l4-egress-explicit-deny-any,CiliumNetworkPolicy,test,l4-self`,
		},
		{
			Namespace: "test-l4",
			Selector:  "test=l4-egress-explicit-deny-tcp",
			Expected: `l4-egress-explicit-deny-tcp,CiliumClusterwideNetworkPolicy,-,l3-baseline
l4-egress-explicit-deny-tcp,CiliumNetworkPolicy,test,l4-self`,
		},
		{
			Namespace: "test-l4",
			Selector:  "test=l4-ingress-all-allow-tcp",
			Expected: `l4-ingress-all-allow-tcp,CiliumClusterwideNetworkPolicy,-,l3-baseline
l4-ingress-all-allow-tcp,CiliumNetworkPolicy,test-l4,l4-ingress-all-allow-tcp`,
		},
	}

	It("should lookup network policies applied to the pods", func() {
		for _, c := range cases {
			By(fmt.Sprintf("checking %v %v", c.Namespace, c.Selector))
			podName := onePodByLabelSelector(Default, c.Namespace, c.Selector)
			args := []string{"lookup", "-o=json", "-n=" + c.Namespace, podName}
			result := runViewerSafe(Default, nil, args...)
			result = fixJsonPodField(Default, result, "subject")
			result = jqSafe(Default, result, "-r", ".[] | [.subject, .kind, .namespace, .name] | @csv")
			resultString := strings.ReplaceAll(string(result), `"`, "")
			Expect(resultString).To(Equal(expectSpecs(c.Expected)), "compare failed. actual: %s\nexpected: %s", resultString, c.Expected)
		}
	})
}

func testLookupManifests() {
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
  enableDefaultDeny:
    egress: true
    ingress: true
  endpointSelector:
    matchLabels:
      k8s:group: test
  ingressDeny:
  - fromEndpoints:
    - matchLabels:
        k8s:test: scapegoat
---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  annotations: {}
  name: l3-baseline-specs
specs:
- egressDeny:
  - toEndpoints:
    - matchLabels:
        k8s:test: scapegoat
  enableDefaultDeny:
    egress: true
    ingress: true
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
  name: l3-ingress-explicit-allow-all
  namespace: test-l3
spec:
  enableDefaultDeny:
    egress: false
    ingress: true
  endpointSelector:
    matchLabels:
      k8s:test: l3-ingress-explicit-allow-all
  ingress:
  - fromEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
        k8s:test: self
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  annotations: {}
  name: l3-ingress-explicit-allow-all-specs
  namespace: test-l3
specs:
- enableDefaultDeny:
    egress: false
    ingress: true
  endpointSelector:
    matchLabels:
      k8s:test: l3-ingress-explicit-allow-all
  ingress:
  - fromEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
        k8s:test: self
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  annotations: {}
  name: l3-self
  namespace: test
spec:
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-explicit-allow-all
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-no-rule
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-implicit-deny-all
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-explicit-deny-all
  - toCIDRSet:
    - cidrGroupSelector:
        matchLabels:
          group: test-group
  egressDeny:
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-egress-explicit-deny-all
  enableDefaultDeny:
    egress: true
    ingress: true
  endpointSelector:
    matchLabels:
      k8s:test: self
  ingress:
  - fromCIDR:
    - 10.100.0.0/16
    - 172.0.0.0/8
  - fromCIDRSet:
    - cidr: 10.120.0.0/16
      except:
      - 10.120.0.0/24
    - cidrGroupRef: cidr-group-1
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  annotations: {}
  name: l3-self-specs
  namespace: test
specs:
- egress:
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-explicit-allow-all
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-no-rule
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-implicit-deny-all
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-ingress-explicit-deny-all
  - toCIDRSet:
    - cidrGroupSelector:
        matchLabels:
          group: test-group
  egressDeny:
  - toEndpoints:
    - matchLabels:
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test-l3
        k8s:test: l3-egress-explicit-deny-all
  enableDefaultDeny:
    egress: true
    ingress: true
  endpointSelector:
    matchLabels:
      k8s:test: self
  ingress:
  - fromCIDR:
    - 10.100.0.0/16
    - 172.0.0.0/8
  - fromCIDRSet:
    - cidr: 10.120.0.0/16
      except:
      - 10.120.0.0/24
    - cidrGroupRef: cidr-group-1`

	It("should lookup referencing policy manifests", func() {
		podName := onePodByLabelSelector(Default, "test-l3", "test=l3-ingress-explicit-allow-all")
		result := strings.TrimSpace(string(runViewerSafe(Default, nil, "lookup", "-n=test-l3", "-m", podName)))
		Expect(result).To(Equal(expected), "compare failed.\nactual: %s\nexpected: %s", result, expected)
	})
}
