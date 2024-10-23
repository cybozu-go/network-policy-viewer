BIN_DIR := $(shell pwd)/bin
TOOLS_DIR := $(BIN_DIR)/download
CACHE_DIR := $(shell pwd)/cache

# Test tools
CILIUM_IMAGE_VERSION := 1.14.14.1
CILIUM_CLI := $(TOOLS_DIR)/cilium
CUSTOMCHECKER := $(TOOLS_DIR)/custom-checker
HELM := helm --repository-cache $(CACHE_DIR)/helm/repository --repository-config $(CACHE_DIR)/helm/repositories.yaml
STATICCHECK := $(TOOLS_DIR)/staticcheck

.PHONY: all
all: help

##@ Basic

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: setup
setup: $(CUSTOMCHECKER) $(STATICCHECK) ## Install necessary tools
	if ! which aqua; then \
		echo 'setup needs aqua.'; \
		exit 1; \
	fi
	aqua install -l
	$(HELM) repo add cilium https://helm.cilium.io/
	$(HELM) repo update cilium

.PHONY: download-cilium-cli
download-cilium-cli:
	mkdir -p $(TOOLS_DIR)
	CONTAINER_ID=$$(docker run --rm --detach --entrypoint pause ghcr.io/cybozu/cilium:$(CILIUM_IMAGE_VERSION)); \
	docker cp $${CONTAINER_ID}:/usr/bin/cilium $(CILIUM_CLI); \
	docker stop $${CONTAINER_ID}

$(CUSTOMCHECKER):
	GOBIN=$(TOOLS_DIR) go install github.com/cybozu-go/golang-custom-analyzer/cmd/custom-checker@latest

$(STATICCHECK):
	GOBIN=$(TOOLS_DIR) go install honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -rf $(CACHE_DIR)

##@ Development

.PHONY: build
build: ## Build network-policy-viewer
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-w -s" -o $(BIN_DIR)/npv ./cmd/npv

.PHONY: build-proxy
build-proxy: ## Build cilium-agent-proxy
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-w -s" -o $(BIN_DIR)/cilium-agent-proxy ./cmd/cilium-agent-proxy

.PHONY: check-generate
check-generate:
	go mod tidy
	git diff --exit-code --name-only

.PHONY: lint
lint: ## Run lint tools
	go vet ./...
	test -z "$$(gofmt -s -l . | tee /dev/stderr)"
	$(STATICCHECK) ./...
	test -z "$$($(CUSTOMCHECKER) -restrictpkg.packages=html/template,log ./... 2>&1 | tee /dev/stderr)"
