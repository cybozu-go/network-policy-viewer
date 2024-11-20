package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testManifestGenerate() {
	cases := []struct {
		Args     []string
		Expected string
	}{
		{
			Args: []string{"--egress", "--allow"},
			Expected: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: testrule
  namespace: test
spec:
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:group: test
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
        k8s:io.cilium.k8s.policy.cluster: default
        k8s:io.cilium.k8s.policy.serviceaccount: default
        k8s:io.kubernetes.pod.namespace: test
        k8s:test: l3-ingress-explicit-allow-all
  endpointSelector:
    matchLabels:
      k8s:group: test
      k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
      k8s:io.cilium.k8s.policy.cluster: default
      k8s:io.cilium.k8s.policy.serviceaccount: default
      k8s:io.kubernetes.pod.namespace: test
      k8s:test: self`,
		},
		{
			Args: []string{"--egress", "--deny"},
			Expected: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: testrule
  namespace: test
spec:
  egressDeny:
  - toEndpoints:
    - matchLabels:
        k8s:group: test
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
        k8s:io.cilium.k8s.policy.cluster: default
        k8s:io.cilium.k8s.policy.serviceaccount: default
        k8s:io.kubernetes.pod.namespace: test
        k8s:test: l3-ingress-explicit-allow-all
  endpointSelector:
    matchLabels:
      k8s:group: test
      k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
      k8s:io.cilium.k8s.policy.cluster: default
      k8s:io.cilium.k8s.policy.serviceaccount: default
      k8s:io.kubernetes.pod.namespace: test
      k8s:test: self`,
		},
		{
			Args: []string{"--ingress", "--allow"},
			Expected: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: testrule
  namespace: test
spec:
  endpointSelector:
    matchLabels:
      k8s:group: test
      k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
      k8s:io.cilium.k8s.policy.cluster: default
      k8s:io.cilium.k8s.policy.serviceaccount: default
      k8s:io.kubernetes.pod.namespace: test
      k8s:test: l3-ingress-explicit-allow-all
  ingress:
  - fromEndpoints:
    - matchLabels:
        k8s:group: test
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
        k8s:io.cilium.k8s.policy.cluster: default
        k8s:io.cilium.k8s.policy.serviceaccount: default
        k8s:io.kubernetes.pod.namespace: test
        k8s:test: self`,
		},
		{
			Args: []string{"--ingress", "--deny"},
			Expected: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: testrule
  namespace: test
spec:
  endpointSelector:
    matchLabels:
      k8s:group: test
      k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
      k8s:io.cilium.k8s.policy.cluster: default
      k8s:io.cilium.k8s.policy.serviceaccount: default
      k8s:io.kubernetes.pod.namespace: test
      k8s:test: l3-ingress-explicit-allow-all
  ingressDeny:
  - fromEndpoints:
    - matchLabels:
        k8s:group: test
        k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name: test
        k8s:io.cilium.k8s.policy.cluster: default
        k8s:io.cilium.k8s.policy.serviceaccount: default
        k8s:io.kubernetes.pod.namespace: test
        k8s:test: self`,
		},
	}

	It("should generate manifests", func() {
		from := "--from=test/" + onePodByLabelSelector(Default, "test", "test=self")
		to := "--to=test/" + onePodByLabelSelector(Default, "test", "test=l3-ingress-explicit-allow-all")
		for _, c := range cases {
			args := append([]string{"manifest", "generate", "--name=testrule", from, to}, c.Args...)
			result := strings.TrimSpace(string(runViewerSafe(Default, nil, args...)))
			Expect(result).To(Equal(c.Expected), "compare failed.\nactual: %s\nexpected: %s", result, c.Expected)
		}
	})
}

func testManifestBlast() {
	expected := `Egress,test,self
Ingress,test,l3-ingress-explicit-allow-all
Ingress,test,l3-ingress-explicit-allow-all`

	It("should show blast radius", func() {
		from := "--from=test/" + onePodByLabelSelector(Default, "test", "test=self")
		to := "--to=test/" + onePodByLabelSelector(Default, "test", "test=l3-ingress-explicit-allow-all")
		result := runViewerSafe(Default, nil, "manifest", "blast", from, to, "-o=json")
		// remove hash suffix from pod names
		result = jqSafe(Default, result, "-r", `[.[] | .name = (.name | split("-") | .[0:5] | join("-"))]`)
		result = jqSafe(Default, result, "-r", `[.[] | .name = (.name | if startswith("self") then "self" else . end)]`)
		result = jqSafe(Default, result, "-r", `.[] | [.direction, .namespace, .name] | @csv`)
		resultString := strings.Replace(string(result), `"`, "", -1)
		Expect(resultString).To(Equal(expected), "compare failed.\nactual: %s\nexpected: %s", resultString, expected)
	})
}
