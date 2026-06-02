package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/labels"
	"golang.org/x/mod/semver"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/cybozu-go/network-policy-viewer/pkg/gvr"
)

type ProxyConfig struct {
	Namespace string
	Selector  string
	Port      uint16
}

type Client struct {
	*client.Client

	dynamicClient       *dynamic.DynamicClient
	node                string
	endpointURL         string
	cachedIdentityCIDRs map[uint32]*net.IPNet
}

var (
	ciliumModuleVersion string
	proxyConfig         *ProxyConfig

	proxyMutex          sync.Mutex
	cachedCiliumClients = make(map[string]*Client)
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		panic("failed to read build info")
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/cilium/cilium" {
			if d.Replace != nil && d.Replace.Version != "" {
				ciliumModuleVersion = d.Replace.Version
			} else {
				ciliumModuleVersion = d.Version
			}
			break
		}
	}
}

func SetProxyConfig(config *ProxyConfig) {
	proxyConfig = config
}

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

	pods, err := c.CoreV1().Pods(proxyConfig.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + targetNode,
		LabelSelector: proxyConfig.Selector,
	})
	if err != nil {
		return "", err
	}
	if num := len(pods.Items); num != 1 {
		err := fmt.Errorf("failed to find cilium-agent-proxy. found %d pods", num)
		return "", err
	}

	podIP := pods.Items[0].Status.PodIP
	return fmt.Sprintf("http://%s:%d", podIP, proxyConfig.Port), nil
}

func getPodEndpointID(ctx context.Context, d *dynamic.DynamicClient, namespace, name string) (int64, error) {
	ep, err := d.Resource(gvr.Endpoint).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}

	endpointID, found, err := unstructured.NestedInt64(ep.Object, "status", "id")
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("endpoint resource %s/%s is broken", namespace, name)
	}

	return endpointID, nil
}

func CreateCiliumClient(ctx context.Context, stderr io.Writer, c *kubernetes.Clientset, d *dynamic.DynamicClient, namespace, name string) (*Client, error) {
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
	proxy := &Client{
		Client:        ciliumClient,
		dynamicClient: d,
		node:          targetNode,
		endpointURL:   endpoint,
	}
	if err := proxy.testAgentVersion(ctx, stderr); err != nil {
		return nil, err
	}

	cachedCiliumClients[endpoint] = proxy
	return proxy, nil
}

func (c *Client) queryProxy(ctx context.Context, path string) ([]byte, error) {
	url := c.endpointURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected HTTP response status: %d, body: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

func (c *Client) testAgentVersion(ctx context.Context, stderr io.Writer) error {
	if stderr == nil {
		panic("internal error; stderr is not specified")
	}

	data, err := c.queryProxy(ctx, "/version")
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

func (c *Client) DumpEndpoint(ctx context.Context, namespace, name string) ([]byte, error) {
	endpointID, err := getPodEndpointID(ctx, c.dynamicClient, namespace, name)
	if err != nil {
		return nil, err
	}

	return c.queryProxy(ctx, fmt.Sprintf("/v1/endpoint/%d", endpointID))
}

func (c *Client) GetEndpointResponse(ctx context.Context, namespace, name string) (*endpoint.GetEndpointIDOK, error) {
	endpointID, err := getPodEndpointID(ctx, c.dynamicClient, namespace, name)
	if err != nil {
		return nil, err
	}

	params := endpoint.GetEndpointIDParams{
		Context: ctx,
		ID:      strconv.FormatInt(endpointID, 10),
	}
	response, err := c.Endpoint.GetEndpointID(&params)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoint information: %w", err)
	}
	if response.Payload == nil ||
		response.Payload.Status == nil ||
		response.Payload.Status.Policy == nil ||
		response.Payload.Status.Policy.Realized == nil ||
		response.Payload.Status.Policy.Realized.L4 == nil ||
		response.Payload.Status.Policy.Realized.L4.Ingress == nil ||
		response.Payload.Status.Policy.Realized.L4.Egress == nil {
		return nil, errors.New("api response is insufficient")
	}
	return response, nil
}

func (c *Client) fetchCIDRIdentities(ctx context.Context) error {
	if c.cachedIdentityCIDRs != nil {
		return nil
	}

	data, err := c.queryProxy(ctx, "/cidr-identities")
	if err != nil {
		return err
	}

	var m []models.Identity
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("failed to unmarshal /cidr-identities: %w", err)
	}

	c.cachedIdentityCIDRs = make(map[uint32]*net.IPNet)
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

		c.cachedIdentityCIDRs[uint32(id.ID)] = cidr
	}
	return nil
}

func (c *Client) GetCIDRForIdentity(ctx context.Context, id uint32) (*net.IPNet, error) {
	if err := c.fetchCIDRIdentities(ctx); err != nil {
		return nil, err
	}

	value, ok := c.cachedIdentityCIDRs[id]
	if !ok {
		return nil, fmt.Errorf("failed to find CIDR identity for %d", id)
	}
	return value, nil
}

func (c *Client) QueryPolicyMap(ctx context.Context, namespace, name string) ([]PolicyEntry, error) {
	endpointID, err := getPodEndpointID(ctx, c.dynamicClient, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod endpoint ID: %w", err)
	}

	data, err := c.queryProxy(ctx, fmt.Sprintf("/policy/%d", endpointID))
	if err != nil {
		return nil, err
	}

	policies := make([]PolicyEntry, 0)
	if err = json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return policies, nil
}
