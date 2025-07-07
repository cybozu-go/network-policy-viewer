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
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func getProxyEndpoint(ctx context.Context, c *kubernetes.Clientset, namespace, name string) (string, error) {
	targetPod, err := c.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	targetNode := targetPod.Spec.NodeName

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

func createCiliumClient(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string) (*client.Client, error) {
	endpoint, err := getProxyEndpoint(ctx, clientset, namespace, name)
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
	cachedCiliumClients[endpoint] = ciliumClient

	return ciliumClient, err
}

type policyEntryKey struct {
	Identity  int `json:"Identity"`
	Direction int `json:"TrafficDirection"`
	Protocol  int `json:"Nexthdr"`
	BigPort   int `json:"DestPortNetwork"` // big endian
}

func (p policyEntryKey) Port() int {
	return ((p.BigPort & 0xFF) << 8) + ((p.BigPort & 0xFF00) >> 8)
}

// For the meanings of the flags, see:
// https://github.com/cilium/cilium/blob/v1.16.3/bpf/lib/common.h#L394
type policyEntry struct {
	Flags   int            `json:"Flags"`
	Packets int            `json:"Packets"`
	Bytes   int            `json:"Bytes"`
	Key     policyEntryKey `json:"Key"`
}

func (p policyEntry) IsDenyRule() bool {
	return (p.Flags & 1) > 0
}

func (p policyEntry) IsIngressRule() bool {
	return !p.IsEgressRule()
}

func (p policyEntry) IsEgressRule() bool {
	return p.Key.Direction > 0
}

func (p policyEntry) IsWildcardProtocol() bool {
	return (p.Flags & 2) > 0
}

func (p policyEntry) IsWildcardPort() bool {
	return (p.Flags & 4) > 0
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

type policyFilter func(ctx context.Context, client *client.Client, p *policyEntry) (bool, error)

func makeCIDRFilter(ingress, egress bool, incl []*net.IPNet, excl []*net.IPNet) policyFilter {
	incl = ip.RemoveCIDRs(incl, excl)

	return func(ctx context.Context, client *client.Client, p *policyEntry) (bool, error) {
		if (p.IsIngressRule() && !ingress) || (p.IsEgressRule() && !egress) {
			return false, nil
		}
		if p.Key.Identity == 0 {
			return true, nil
		}

		// If the identity is not locally-scoped, it is not representing a CIDR
		idObj := identity.NumericIdentity(p.Key.Identity)
		if !idObj.HasLocalScope() {
			return false, nil
		}

		// Retrieve identity information
		params := policy.GetIdentityIDParams{
			Context: ctx,
			ID:      strconv.FormatInt(int64(p.Key.Identity), 10),
		}
		response, err := client.Policy.GetIdentityID(&params)
		if err != nil {
			return false, fmt.Errorf("failed to get identity: %w", err)
		}
		if !slices.Contains(response.Payload.Labels, "reserved:world") {
			return false, nil
		}

		// Compute leaf CIDR of the identity
		lbls := labels.NewLabelsFromModel(response.Payload.Labels)
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

func filterPolicyMap(ctx context.Context, client *client.Client, policies []policyEntry, pred policyFilter) ([]policyEntry, error) {
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
