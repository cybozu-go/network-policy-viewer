package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
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

	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)
	renderJSON(w, r.URL.Path, buf.Bytes(), http.StatusOK)
}

func handleCIDRIdentities(w http.ResponseWriter, r *http.Request) {
	url := "http://localhost/v1/identity"
	resp, err := socketClient.Get(url)
	if err != nil {
		renderError(w, r.URL.Path, "failed to call Cilium API", http.StatusInternalServerError)
		return
	}

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
				return strings.HasPrefix(l, "cidr:")
			})
		}
		return true
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
		Cilium statusCilium `json:"cilium,omitempty"`
	}

	var s status
	if err := json.Unmarshal(stdout, &s); err != nil {
		renderError(w, r.URL.Path, "failed to parse status", http.StatusInternalServerError)
		return
	}

	// Convert to number to avoid exposing unexpected content
	var major, minor, revision int
	fmt.Sscanf(s.Cilium.Msg, "%d.%d.%d", &major, &minor, &revision)

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
	socketClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	server := http.Server{
		Addr:    ":8080",
		Handler: nil,
	}

	http.HandleFunc("/v1/endpoint/", handleEndpoint)
	http.HandleFunc("/cidr-identities", handleCIDRIdentities)
	http.HandleFunc("/policy/", handlePolicy)
	http.HandleFunc("/version", handleVersion)

	return server.ListenAndServe()
}
