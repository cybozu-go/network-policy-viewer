# Build the manager binary
FROM ghcr.io/cybozu/golang:1.23-jammy AS builder

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/cilium-agent-proxy/ cmd/cilium-agent-proxy/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o cilium-agent-proxy ./cmd/cilium-agent-proxy

# Compose the manager container
FROM ghcr.io/cybozu/ubuntu:22.04
LABEL org.opencontainers.image.source=https://github.com/cybozu-go/network-policy-viewer

WORKDIR /
COPY --from=builder /work/cilium-agent-proxy /

USER 10000:10000
ENTRYPOINT ["/cilium-agent-proxy"]