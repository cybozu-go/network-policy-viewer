package sub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
)

const (
	ciliumPath = "/cilium"
)

func runCommand(path string, input []byte, args ...string) ([]byte, []byte, error) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd := exec.Command(path, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	if err := cmd.Run(); err != nil {
		_, file := filepath.Split(path)
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("%s failed with %s: stderr=%s", file, err, stderr)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func renderJSON(w http.ResponseWriter, path string, data []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		slog.Error("failed to write response", slog.String("path", path))
	}
}

func renderError(w http.ResponseWriter, path string, message string, status int) {
	slog.Info(message, slog.String("path", path), slog.Int("status", status))
	ret := make(map[string]string)
	ret["error"] = message
	ret["status"] = strconv.Itoa(status)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(ret); err != nil {
		slog.Error("failed to write response", slog.String("path", path))
	}
}
