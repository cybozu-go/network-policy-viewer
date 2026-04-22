package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type cachedIdentity struct {
	identity *models.Identity
	cidr     *net.IPNet
}

type proxyClient struct {
	*client.Client

	node                 string
	endpointURL          string
	cachedCIDRIdentities map[uint32]*cachedIdentity
}

var (
	proxyMutex          sync.Mutex
	cachedCiliumClients = make(map[string]*proxyClient)
)

func getPodNodeName(ctx context.Context, c *kubernetes.Clientset, namespace, name string) (string, error) {
	pod, err := c.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return pod.Spec.NodeName, nil
}

func getProxyEndpoint(ctx context.Context, c *kubernetes.Clientset, namespace, name string) (string, error) {
	targetNode, err := getPodNodeName(ctx, c, namespace, name)
	if err != nil {
		return "", err
	}

	pods, err := c.CoreV1().Pods(rootOptions.proxyNamespace).List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + targetNode,
		LabelSelector: rootOptions.proxySelector,
	})
	if err != nil {
		return "", err
	}
	if num := len(pods.Items); num != 1 {
		err := fmt.Errorf("failed to find cilium-agent-proxy. found %d pods", num)
		return "", err
	}

	podIP := pods.Items[0].Status.PodIP
	return fmt.Sprintf("http://%s:%d", podIP, rootOptions.proxyPort), nil
}

func createCiliumClient(ctx context.Context, stderr io.Writer, c *kubernetes.Clientset, namespace, name string) (*proxyClient, error) {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	targetNode, err := getPodNodeName(ctx, c, namespace, name)
	if err != nil {
		return nil, err
	}

	endpoint, err := getProxyEndpoint(ctx, c, namespace, name)
	if err != nil {
		return nil, err
	}

	if cached, ok := cachedCiliumClients[endpoint]; ok {
		return cached, nil
	}

	ciliumClient, err := client.NewClient(endpoint)
	if err != nil {
		return nil, err
	}
	proxy := &proxyClient{
		Client:      ciliumClient,
		node:        targetNode,
		endpointURL: endpoint,
	}
	if err := proxy.testAgentVersion(ctx, stderr); err != nil {
		return nil, err
	}

	cachedCiliumClients[endpoint] = proxy
	return proxy, nil
}

func (c *proxyClient) testAgentVersion(ctx context.Context, stderr io.Writer) error {
	url := c.endpointURL + "/version"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to request /version: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result struct {
		Cilium string `json:"cilium,omitempty"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}

	agentVersion := semver.MajorMinor(result.Cilium)
	moduleVersion := semver.MajorMinor(ciliumModuleVersion)
	if agentVersion != moduleVersion {
		fmt.Fprintf(stderr, "Warning: %s is running Cilium %s, but npv is built for %s. Result may be incorrect.\n", c.node, agentVersion, moduleVersion)
	}

	return nil
}

func (c *proxyClient) fetchCIDRIdentities() error {
	if c.cachedCIDRIdentities == nil {
		url := c.endpointURL + "/cidr-identities"
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed to request /cidr-identities: %w", err)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read /cidr-identities: %w", err)
		}

		var m []models.Identity
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("failed to unmarshal /cidr-identities: %w", err)
		}

		c.cachedCIDRIdentities = make(map[uint32]*cachedIdentity)
		for _, id := range m {
			lbls := labels.NewLabelsFromModel(id.Labels)
			cidrModel := lbls.GetFromSource(labels.LabelSourceCIDR).GetPrintableModel()
			if len(cidrModel) != 1 {
				return fmt.Errorf("unexpected CIDR label for identity %d", id.ID)
			}
			parts := strings.Split(cidrModel[0], ":")
			if len(parts) != 2 {
				return fmt.Errorf("failed to parse CIDR label for identity %d", id.ID)
			}
			_, cidr, err := net.ParseCIDR(parts[1])
			if err != nil {
				return fmt.Errorf("failed to parse CIDR for identity %d", id.ID)
			}

			c.cachedCIDRIdentities[uint32(id.ID)] = &cachedIdentity{
				identity: &id,
				cidr:     cidr,
			}
		}
	}
	return nil
}

func (c *proxyClient) listCIDRIdentity() ([]uint32, error) {
	if err := c.fetchCIDRIdentities(); err != nil {
		return nil, err
	}
	// for k, v := range c.cachedCIDRIdentities {

	// }
	return nil, nil
}

func (c *proxyClient) getCIDRIdentity(ctx context.Context, id uint32) (*models.Identity, error) {
	if err := c.fetchCIDRIdentities(); err != nil {
		return nil, err
	}

	value, ok := c.cachedCIDRIdentities[id]
	if !ok {
		return nil, fmt.Errorf("failed to found CIDR identity for %d", id)
	}
	return value.identity, nil
}

// For the meanings of the flags, see:
// https://github.com/cilium/cilium/blob/v1.16.12/bpf/lib/common.h#L396
type policyEntry struct {
	policymap.PolicyEntryDump
}

func (p policyEntry) IsAllow() bool {
	return !p.IsDeny()
}

func (p policyEntry) IsIngress() bool {
	return !p.IsEgress()
}

func (p policyEntry) IsEgress() bool {
	return p.Key.TrafficDirection == uint8(trafficdirection.Egress)
}

func (p policyEntry) GetProtocol() uint8 {
	return p.Key.Nexthdr
}

func (p policyEntry) IsWildcardProtocol() bool {
	return p.Key.Nexthdr == 0
}

func (p policyEntry) IsWildcardPort() bool {
	return p.Key.GetDestPort() == 0
}

func queryPolicyMap(ctx context.Context, clientset *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, namespace, name string) ([]policyEntry, error) {
	endpointID, err := getPodEndpointID(ctx, dynamicClient, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod endpoint ID: %w", err)
	}

	url, err := getProxyEndpoint(ctx, clientset, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy endpoint: %w", err)
	}

	url = fmt.Sprintf("%s/policy/%d", url, endpointID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to request policy: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	policies := make([]policyEntry, 0)
	if err = json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return policies, nil
}

type policyFilter func(ctx context.Context, client *proxyClient, p *policyEntry) (bool, error)

func makeBasicFilter(ingress, egress, allowed, denied, used, unused bool) policyFilter {
	if ingress && egress && allowed && denied && used && unused {
		// no filter
		return nil
	}
	return func(ctx context.Context, client *proxyClient, p *policyEntry) (bool, error) {
		ret := true
		switch {
		case p.IsIngress():
			ret = ret && ingress
		case p.IsEgress():
			ret = ret && egress
		}
		switch {
		case p.IsAllow():
			ret = ret && allowed
		case p.IsDeny():
			ret = ret && denied
		}
		switch {
		case p.Bytes > 0:
			ret = ret && used
		case p.Bytes == 0:
			ret = ret && unused
		}
		return ret, nil
	}
}

func makeIdentityFilter(ingress, egress bool, id uint32) policyFilter {
	return func(ctx context.Context, client *proxyClient, p *policyEntry) (bool, error) {
		if (p.IsIngress() && !ingress) || (p.IsEgress() && !egress) {
			return false, nil
		}
		if p.Key.Identity == 0 {
			return true, nil
		}

		// This filter is looking for a global identity
		idObj := identity.NumericIdentity(p.Key.Identity)
		if idObj.HasLocalScope() {
			return false, nil
		}
		return (p.Key.Identity == 0) || (p.Key.Identity == id), nil
	}
}

func makeCIDRFilter(ingress, egress bool, incl []*net.IPNet, excl []*net.IPNet) policyFilter {
	incl = ip.RemoveCIDRs(incl, excl)

	return func(ctx context.Context, client *proxyClient, p *policyEntry) (bool, error) {
		if (p.IsIngress() && !ingress) || (p.IsEgress() && !egress) {
			return false, nil
		}

		idObj := identity.NumericIdentity(p.Key.Identity)
		switch idObj {
		case identity.IdentityUnknown,
			identity.ReservedIdentityWorld,
			identity.ReservedIdentityWorldIPv4,
			identity.ReservedIdentityWorldIPv6:
			return true, nil
		}

		// If the identity is not locally-scoped, it is not representing a CIDR
		if !idObj.HasLocalScope() {
			return false, nil
		}

		// Retrieve identity information
		cidrID, err := client.getCIDRIdentity(ctx, p.Key.Identity)
		if err != nil {
			return false, err
		}
		if !slices.Contains(cidrID.Labels, "reserved:world") {
			return false, nil
		}

		// Compute leaf CIDR of the identity
		lbls := labels.NewLabelsFromModel(cidrID.Labels)
		cidrModel := lbls.GetFromSource(labels.LabelSourceCIDR).GetPrintableModel()
		if len(cidrModel) != 1 {
			return false, errors.New("internal error")
		}
		_, idCIDR, err := net.ParseCIDR(strings.Split(cidrModel[0], ":")[1])
		if err != nil {
			return false, err
		}

		// Check
		for _, cidr := range incl {
			if isChildCIDR(cidr, idCIDR) || isChildCIDR(idCIDR, cidr) {
				return true, nil
			}
		}
		return false, nil
	}
}

func makeAllFilter(filters ...policyFilter) policyFilter {
	// Please make sure to put a basic filter first for faster computation
	arr := make([]policyFilter, 0)
	for _, f := range filters {
		if f != nil {
			arr = append(arr, f)
		}
	}
	switch len(arr) {
	case 0:
		return nil
	case 1:
		return arr[0]
	default:
		return func(ctx context.Context, client *proxyClient, p *policyEntry) (bool, error) {
			for _, f := range arr {
				result, err := f(ctx, client, p)
				if !result || err != nil {
					return result, err
				}
			}
			return true, nil
		}
	}
}

func filterPolicyMap(ctx context.Context, client *proxyClient, policies []policyEntry, pred policyFilter) ([]policyEntry, error) {
	if pred == nil {
		return policies, nil
	}

	// If any error is observed, cancel the remaining work and returns the error
	var err error
	policies = slices.DeleteFunc(policies, func(p policyEntry) bool {
		if err != nil {
			return false
		}
		var ok bool
		ok, err = pred(ctx, client, &p)
		return !ok
	})
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func mapNodeReduce[T any](pods []*corev1.Pod, initFunc func() T, mapFunc func(*corev1.Pod) T, reduceFunc func(T, T) T) T {
	var mu sync.Mutex
	pods = slices.Clone(pods)
	nodes := make(map[string]bool)
	for _, p := range pods {
		nodes[p.Spec.NodeName] = false
	}

	numJobs := min(rootOptions.jobs, len(pods), len(nodes))
	if numJobs == 0 {
		return initFunc()
	}

	pick := func() (*corev1.Pod, bool) {
		mu.Lock()
		defer mu.Unlock()
		for i := len(pods) - 1; i >= 0; i-- {
			p := pods[i]
			if !nodes[p.Spec.NodeName] {
				nodes[p.Spec.NodeName] = true
				pods = slices.Delete(pods, i, i+1)
				return p, true
			}
		}
		return nil, false
	}
	release := func(p *corev1.Pod) {
		mu.Lock()
		defer mu.Unlock()
		if !nodes[p.Spec.NodeName] {
			panic("internal error")
		}
		nodes[p.Spec.NodeName] = false
	}

	var wg sync.WaitGroup
	values := make([]T, numJobs)
	for i := 0; i < numJobs; i++ {
		wg.Go(func() {
			values[i] = initFunc()
			for {
				p, found := pick()
				if !found {
					return
				}
				v := mapFunc(p)
				release(p)

				values[i] = reduceFunc(values[i], v)
			}
		})
	}
	wg.Wait()

	result := values[0]
	for i := 1; i < numJobs; i++ {
		result = reduceFunc(result, values[i])
	}
	return result
}
