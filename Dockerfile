# Build the manager binary
FROM ghcr.io/cybozu/golang:1.26.5.2_noble@sha256:419e350acc85bb2603c45e15e12c3238a1ec765cb58f5eb14ef7adf8bea9748f AS builder

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/cilium-agent-proxy/ cmd/cilium-agent-proxy/
COPY pkg/server/ pkg/server/
COPY Makefile Makefile

# Build
RUN make build-proxy

# Compose the manager container
FROM scratch
LABEL org.opencontainers.image.source=https://github.com/cybozu-go/network-policy-viewer

WORKDIR /
COPY bin/download/cilium-dbg /
COPY --from=builder /work/bin/cilium-agent-proxy /

ENTRYPOINT ["/cilium-agent-proxy"]
