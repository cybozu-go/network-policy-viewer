package app

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/cybozu-go/network-policy-viewer/pkg/server"
)

const socketPath = "/var/run/cilium/cilium.sock"

var (
	socketClient *http.Client
)

func handleEndpoint(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Path[len("/v1/endpoint/"):]
	if len(param) == 0 {
		renderError(w, r.URL.Path, "failed to read endpoint ID", http.StatusBadRequest)
		return
	}

	// Convert to number to avoid parameter injection
	endpoint, err := strconv.Atoi(param)
	if err != nil {
		renderError(w, r.URL.Path, "failed to read endpoint ID", http.StatusBadRequest)
		return
	}

	url := fmt.Sprintf("http://localhost/v1/endpoint/%d", endpoint)
	resp, err := socketClient.Get(url)
	if err != nil {
		renderError(w, r.URL.Path, "failed to call Cilium API", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		renderError(w, r.URL.Path, "failed to write response", http.StatusInternalServerError)
		return
	}
	renderJSON(w, r.URL.Path, buf.Bytes(), http.StatusOK)
}

func handleCIDRIdentities(w http.ResponseWriter, r *http.Request) {
	url := "http://localhost/v1/identity"
	resp, err := socketClient.Get(url)
	if err != nil {
		renderError(w, r.URL.Path, "failed to call Cilium API", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// https://github.com/cilium/cilium/blob/main/api/v1/models/identity.go
	type Identity struct {
		ID     int64    `json:"id,omitempty"`
		Labels []string `json:"labels,omitempty"`
	}
	var ids []Identity
	{
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			renderError(w, r.URL.Path, "failed to read data", http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(data, &ids); err != nil {
			renderError(w, r.URL.Path, "failed to unmarshal result", http.StatusInternalServerError)
			return
		}
	}
	ids = slices.DeleteFunc(ids, func(i Identity) bool {
		// https://docs.cilium.io/en/stable/internals/security-identities/
		if (1<<24) <= i.ID && i.ID < (1<<25) {
			return !slices.ContainsFunc(i.Labels, func(l string) bool {
				return strings.HasPrefix(l, "cidr:") || strings.HasPrefix(l, "cidrgroup:")
			})
		}
		return true
	})
	slices.SortFunc(ids, func(x, y Identity) int {
		return cmp.Compare(x.ID, y.ID)
	})

	data, err := json.Marshal(ids)
	if err != nil {
		renderError(w, r.URL.Path, "failed to marshal result", http.StatusInternalServerError)
		return
	}
	renderJSON(w, r.URL.Path, data, http.StatusOK)
}

func handlePolicy(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Path[len("/policy/"):]
	if len(param) == 0 {
		renderError(w, r.URL.Path, "failed to read endpoint ID", http.StatusBadRequest)
		return
	}

	// Convert to number to avoid parameter injection
	endpoint, err := strconv.Atoi(param)
	if err != nil {
		renderError(w, r.URL.Path, "failed to read endpoint ID", http.StatusBadRequest)
		return
	}

	stdout, _, err := runCommand(ciliumPath, nil, "bpf", "policy", "get", strconv.Itoa(endpoint), "-ojson")
	if err != nil {
		renderError(w, r.URL.Path, "failed to read BPF map", http.StatusInternalServerError)
		return
	}

	renderJSON(w, r.URL.Path, stdout, http.StatusOK)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	stdout, _, err := runCommand(ciliumPath, nil, "status", "-ojson")
	if err != nil {
		renderError(w, r.URL.Path, "failed to read status", http.StatusInternalServerError)
		return
	}

	type statusCilium struct {
		Msg string `json:"msg,omitempty"`
	}
	type status struct {
		Cilium statusCilium `json:"cilium"`
	}

	var s status
	if err := json.Unmarshal(stdout, &s); err != nil {
		renderError(w, r.URL.Path, "failed to parse status", http.StatusInternalServerError)
		return
	}

	// Convert to number to avoid exposing unexpected content
	var major, minor, revision int
	if _, err := fmt.Sscanf(s.Cilium.Msg, "%d.%d.%d", &major, &minor, &revision); err != nil {
		renderError(w, r.URL.Path, "failed to parse version", http.StatusInternalServerError)
		return
	}

	// Do not expose excessive info to client
	var result struct {
		Cilium string `json:"cilium,omitempty"`
	}
	result.Cilium = fmt.Sprintf("v%d.%d.%d", major, minor, revision)

	data, err := json.Marshal(result)
	if err != nil {
		renderError(w, r.URL.Path, "failed to marshal result", http.StatusInternalServerError)
		return
	}
	renderJSON(w, r.URL.Path, data, http.StatusOK)
}

func subMain() error {
	useTLS := rootOptions.tlsCertFile != ""
	if (rootOptions.tlsCertFile == "") != (rootOptions.tlsPrivateKeyFile == "") {
		return fmt.Errorf("--tls-cert-file and --tls-private-key-file must be specified together")
	}

	socketClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	port := server.DefaultHTTPPort
	tlsMode := "disabled"
	if useTLS {
		port = server.DefaultHTTPSPort
		tlsMode = "enabled"
	}
	addr := fmt.Sprintf(":%d", port)

	server := http.Server{
		Addr:    addr,
		Handler: nil,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	http.HandleFunc("/v1/endpoint/", handleEndpoint)
	http.HandleFunc("/cidr-identities", handleCIDRIdentities)
	http.HandleFunc("/policy/", handlePolicy)
	http.HandleFunc("/version", handleVersion)

	slog.Info(fmt.Sprintf("starting cilium-agent-proxy with TLS %s on %s", tlsMode, addr))
	if useTLS {
		return server.ListenAndServeTLS(rootOptions.tlsCertFile, rootOptions.tlsPrivateKeyFile)
	}
	return server.ListenAndServe()
}
