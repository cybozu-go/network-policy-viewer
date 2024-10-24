package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
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

func handleIdentity(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Path[len("/v1/identity/"):]
	if len(param) == 0 {
		renderError(w, r.URL.Path, "failed to read identity", http.StatusBadRequest)
		return
	}

	// Convert to number to avoid parameter injection
	identity, err := strconv.Atoi(param)
	if err != nil {
		renderError(w, r.URL.Path, "failed to read identity", http.StatusBadRequest)
		return
	}

	url := fmt.Sprintf("http://localhost/v1/identity/%d", identity)
	resp, err := socketClient.Get(url)
	if err != nil {
		renderError(w, r.URL.Path, "failed to call Cilium API", http.StatusInternalServerError)
		return
	}

	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)
	renderJSON(w, r.URL.Path, buf.Bytes(), http.StatusOK)
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
	http.HandleFunc("/v1/identity/", handleIdentity)
	http.HandleFunc("/policy/", handlePolicy)

	return server.ListenAndServe()
}
