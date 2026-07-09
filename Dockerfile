# Build the manager binary
FROM ghcr.io/cybozu/golang:1.26-noble AS builder

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/cilium-agent-proxy/ cmd/cilium-agent-proxy/
COPY Makefile Makefile

# Build
RUN make build-proxy

# ----------------------------------------
# Build cilium-agent-proxy container
FROM scratch AS runtime
LABEL org.opencontainers.image.source=https://github.com/cybozu-go/network-policy-viewer

WORKDIR /
COPY bin/download/cilium-dbg /
COPY --from=builder /work/bin/cilium-agent-proxy /

ENTRYPOINT ["/cilium-agent-proxy"]

# ----------------------------------------
# Generate SBOM
FROM ghcr.io/cybozu/ubuntu:24.04 AS scanner
COPY bin/download/syft /usr/local/bin/syft
RUN --mount=type=bind,from=runtime,source=/,target=/scanroot,readonly \
    /usr/local/bin/syft dir:/scanroot \
        --base-path /scanroot \
        --source-name runtime \
        -o syft-json=/usr/share/sbom/image.syft.json

# ----------------------------------------
# Embed SBOM
FROM runtime
COPY --from=scanner /usr/share/sbom /usr/share/sbom
