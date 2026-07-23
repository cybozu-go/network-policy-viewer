package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"

	apiclient "github.com/cilium/cilium/api/v1/client"
	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	runtimeclient "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cybozu-go/network-policy-viewer/pkg/cidr"
	"github.com/cybozu-go/network-policy-viewer/pkg/server"
)

type Config struct {
	Namespace             string
	Selector              string
	Port                  uint16
	TLS                   bool
	TLSCAFile             string
	TLSServerName         string
	TLSInsecureSkipVerify bool
}

type Client struct {
	*client.Client

	k8sClient   k8sclient.Client
	node        string
	endpointURL string
	httpClient  *http.Client

	cidrGroups       map[string][]netip.Prefix
	prefixIdentities []netip.Prefix
	identityPrefixes map[uint32][]netip.Prefix
	identityCIDRSets map[uint32]cidr.Set
}

var (
	ciliumModuleVersion string
	config              *Config

	proxyMutex          sync.Mutex
	cachedCIDRGroups    map[string][]netip.Prefix
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
	config = &Config{}
}

func SetConfig(c *Config) error {
	if c.TLS {
		if c.TLSServerName == "" {
			return errors.New("--proxy-tls-server-name must be specified with --proxy-tls")
		}
	} else {
		if c.TLSCAFile != "" || c.TLSServerName != "" || c.TLSInsecureSkipVerify {
			return errors.New("proxy TLS options require --proxy-tls")
		}
	}
	config = c
	return nil
}

func getPodNodeName(ctx context.Context, c k8sclient.Client, namespace, name string) (string, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &pod); err != nil {
		return "", err
	}
	return pod.Spec.NodeName, nil
}

func getProxyEndpoint(ctx context.Context, c k8sclient.Client, namespace, name string) (string, error) {
	selector, err := k8slabels.Parse(config.Selector)
	if err != nil {
		return "", err
	}

	targetNode, err := getPodNodeName(ctx, c, namespace, name)
	if err != nil {
		return "", err
	}

	var pods corev1.PodList
	if err := c.List(ctx, &pods, &k8sclient.ListOptions{
		Namespace:     config.Namespace,
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", targetNode),
		LabelSelector: selector,
	}); err != nil {
		return "", err
	}
	if num := len(pods.Items); num != 1 {
		err := fmt.Errorf("failed to find cilium-agent-proxy. found %d pods", num)
		return "", err
	}

	podIP := pods.Items[0].Status.PodIP
	port := config.Port
	if config.TLS {
		if port == 0 {
			port = server.DefaultHTTPSPort
		}
		return fmt.Sprintf("https://%s:%d", podIP, port), nil
	} else {
		if port == 0 {
			port = server.DefaultHTTPPort
		}
		return fmt.Sprintf("http://%s:%d", podIP, port), nil
	}
}

func getPodEndpointID(ctx context.Context, c k8sclient.Client, namespace, name string) (int64, error) {
	var ep ciliumv2.CiliumEndpoint
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &ep); err != nil {
		return 0, err
	}
	return ep.Status.ID, nil
}

func fetchCIDRGroupsLocked(ctx context.Context, c k8sclient.Client) error {
	if cachedCIDRGroups != nil {
		return nil
	}

	var resources ciliumv2alpha1.CiliumCIDRGroupList
	if err := c.List(ctx, &resources); err != nil {
		return err
	}

	tmp := make(map[string][]netip.Prefix)
	for _, g := range resources.Items {
		cidrs := make([]netip.Prefix, len(g.Spec.ExternalCIDRs))
		for i, cs := range g.Spec.ExternalCIDRs {
			c, err := netip.ParsePrefix(string(cs))
			if err != nil {
				return err
			}
			cidrs[i] = c
		}
		tmp[g.GetName()] = cidrs
	}
	cachedCIDRGroups = tmp
	return nil
}

func newHTTPClient() (*http.Client, error) {
	if !config.TLS {
		return http.DefaultClient, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         config.TLSServerName,
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}

	if config.TLSCAFile != "" {
		roots := x509.NewCertPool()
		data, err := os.ReadFile(config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read proxy TLS CA file: %w", err)
		}

		if ok := roots.AppendCertsFromPEM(data); !ok {
			return nil, fmt.Errorf("failed to parse proxy TLS CA file %q", config.TLSCAFile)
		}
		tlsConfig.RootCAs = roots
	}

	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not *http.Transport")
	}

	transport := baseTransport.Clone()
	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Transport: transport,
	}, nil
}

func newCiliumClient(endpoint string, httpClient *http.Client) (*client.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy endpoint URL: %w", err)
	}

	transport := runtimeclient.NewWithClient(
		u.Host,
		apiclient.DefaultBasePath,
		[]string{u.Scheme},
		httpClient,
	)

	return &client.Client{
		CiliumAPI: *apiclient.New(transport, strfmt.Default),
	}, nil
}

func CreateCiliumClient(ctx context.Context, stderr io.Writer, c k8sclient.Client, namespace, name string) (*Client, error) {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	if err := fetchCIDRGroupsLocked(ctx, c); err != nil {
		return nil, err
	}

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

	httpClient, err := newHTTPClient()
	if err != nil {
		return nil, err
	}

	ciliumClient, err := newCiliumClient(endpoint, httpClient)
	if err != nil {
		return nil, err
	}
	proxy := &Client{
		Client:           ciliumClient,
		k8sClient:        c,
		node:             targetNode,
		endpointURL:      endpoint,
		httpClient:       httpClient,
		cidrGroups:       cachedCIDRGroups,
		identityCIDRSets: make(map[uint32]cidr.Set),
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

	resp, err := c.httpClient.Do(req)
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
	endpointID, err := getPodEndpointID(ctx, c.k8sClient, namespace, name)
	if err != nil {
		return nil, err
	}

	return c.queryProxy(ctx, fmt.Sprintf("/v1/endpoint/%d", endpointID))
}

func (c *Client) GetEndpointResponse(ctx context.Context, namespace, name string) (*endpoint.GetEndpointIDOK, error) {
	endpointID, err := getPodEndpointID(ctx, c.k8sClient, namespace, name)
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

func (c *Client) prepareCIDRs(ctx context.Context) error {
	if c.prefixIdentities != nil {
		return nil
	}

	data, err := c.queryProxy(ctx, "/cidr-identities")
	if err != nil {
		return err
	}

	// Example:
	// - id: 16777218
	//   labels:
	//     - cidrgroup:group=test-group
	//     - cidrgroup:io.cilium.policy.cidrgroupname/cidr-group-1
	//     - reserved:world
	// - id: 16777220
	//   labels:
	//     - cidr:1.1.1.1/32
	//     - reserved:world

	var m []models.Identity
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("failed to unmarshal /cidr-identities: %w", err)
	}

	ip := make(map[uint32][]netip.Prefix)
	pi := make([]netip.Prefix, 0)

OUTER:
	for _, id := range m {
		lbls := labels.NewLabelsFromModel(id.Labels)
		{
			groupModel := lbls.GetFromSource(labels.LabelSourceCIDRGroup)
			for k := range groupModel {
				if strings.HasPrefix(k, api.LabelPrefixGroupName) {
					li := strings.Split(k, "/")
					if len(li) < 2 {
						return fmt.Errorf("unexpected CIDRGroup label for identity %d", id.ID)
					}

					name := li[1]
					groupCIDRs, ok := c.cidrGroups[name]
					if !ok {
						return fmt.Errorf("failed to find CiliumCIDRGroup %s", name)
					}
					ip[uint32(id.ID)] = groupCIDRs
					pi = append(pi, groupCIDRs...)
					continue OUTER
				}
			}
		}

		cidrModel := lbls.GetFromSource(labels.LabelSourceCIDR).GetPrintableModel()
		if len(cidrModel) != 1 {
			return fmt.Errorf("unexpected CIDR label for identity %d", id.ID)
		}
		parts := strings.Split(cidrModel[0], ":")
		if len(parts) != 2 {
			return fmt.Errorf("failed to parse CIDR label for identity %d", id.ID)
		}
		cidr, err := netip.ParsePrefix(parts[1])
		if err != nil {
			return fmt.Errorf("failed to parse CIDR for identity %d", id.ID)
		}

		ip[uint32(id.ID)] = []netip.Prefix{cidr}
		pi = append(pi, cidr)
	}
	slices.SortFunc(pi, func(x, y netip.Prefix) int {
		return x.Compare(y)
	})
	c.identityPrefixes = ip
	c.prefixIdentities = pi
	return nil
}

func (c *Client) GetCIDRForIdentity(ctx context.Context, id uint32) (*cidr.Set, error) {
	// Starting with Cilium 1.17, external CIDRs in the ipcache are no longer
	// exclusive, and the exact identity is determined by LPM. In addition,
	// multiple CIDRs may be assigned to the same identity.
	//
	// To determine which IP addresses belong to a specific identity, we need to
	// collect all CIDRs for that identity from the ipcache, then exclude CIDRs
	// associated with other identities that are subsets of those CIDRs.
	if err := c.prepareCIDRs(ctx); err != nil {
		return nil, err
	}
	if s, ok := c.identityCIDRSets[id]; ok {
		return &s, nil
	}

	incl, ok := c.identityPrefixes[id]
	if !ok {
		return nil, fmt.Errorf("failed to find CIDR identity for %d", id)
	}

	excl := make([]netip.Prefix, 0)
	for _, cidr := range incl {
		ix, ok := slices.BinarySearchFunc(c.prefixIdentities, cidr, func(x, y netip.Prefix) int {
			return x.Compare(y)
		})
		if !ok {
			return nil, fmt.Errorf("failed to find CIDR for %d", id)
		}
		for i := ix; i < len(c.prefixIdentities); i++ {
			p := c.prefixIdentities[i]
			if cidr == p {
				continue
			}
			if !cidr.Contains(p.Addr()) {
				break
			}
			excl = append(excl, p)
		}
	}

	ret := cidr.NewSet(cidr.NewArray(incl), cidr.NewArray(excl))
	c.identityCIDRSets[id] = ret
	return &ret, nil
}

func (c *Client) QueryPolicyMap(ctx context.Context, namespace, name string) ([]PolicyEntry, error) {
	endpointID, err := getPodEndpointID(ctx, c.k8sClient, namespace, name)
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
