package sub

import (
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
		fmt.Fprint(w, "error\n")
		return
	}

	// Convert to number to avoid parameter injection
	endpoint, err := strconv.Atoi(param)
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	url := fmt.Sprintf("http://localhost/v1/endpoint/%d", endpoint)
	resp, err := socketClient.Get(url)
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func handleIdentity(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Path[len("/v1/identity/"):]
	if len(param) == 0 {
		fmt.Fprint(w, "error\n")
		return
	}

	// Convert to number to avoid parameter injection
	identity, err := strconv.Atoi(param)
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	url := fmt.Sprintf("http://localhost/v1/identity/%d", identity)
	resp, err := socketClient.Get(url)
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func handlePolicy(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "error\n")
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
