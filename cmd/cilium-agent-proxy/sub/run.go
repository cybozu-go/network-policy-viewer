package sub

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
)

const socketPath = "/var/run/cilium/cilium.sock"

var (
	endpointPattern *regexp.Regexp
	identityPattern *regexp.Regexp
)

func handleEndpoint(w http.ResponseWriter, r *http.Request) {
	match := endpointPattern.FindStringSubmatch(r.URL.Path)
	if match == nil || len(match) < 2 {
		fmt.Fprint(w, "error\n")
		return
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	// Convert to number to avoid possible parameter injection
	endpoint, err := strconv.Atoi(match[1])
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	url := fmt.Sprintf("http://localhost/v1/endpoint/%d", endpoint)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	io.Copy(w, resp.Body)
}

func handleIdentity(w http.ResponseWriter, r *http.Request) {
	match := identityPattern.FindStringSubmatch(r.URL.Path)
	if match == nil || len(match) < 2 {
		fmt.Fprint(w, "error\n")
		return
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	// Convert to number to avoid possible parameter injection
	identity, err := strconv.Atoi(match[1])
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	url := fmt.Sprintf("http://localhost/v1/identity/%d", identity)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprint(w, "error\n")
		return
	}

	io.Copy(w, resp.Body)
}

func handlePolicy(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "policy")
}

func subMain() error {
	pattern, err := regexp.Compile(`^/endpoint/(?P<endpoint>\d+)$`)
	endpointPattern = pattern
	if err != nil {
		return err
	}

	pattern, err = regexp.Compile(`^/identity/(?P<identity>\d+)$`)
	identityPattern = pattern
	if err != nil {
		return err
	}

	server := http.Server{
		Addr:    ":8080",
		Handler: nil,
	}

	http.HandleFunc("/endpoint/", handleEndpoint)
	http.HandleFunc("/identity/", handleIdentity)
	http.HandleFunc("/policy/", handlePolicy)

	return server.ListenAndServe()
}
