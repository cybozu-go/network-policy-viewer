BIN_DIR := $(shell pwd)/bin
TOOLS_DIR := $(BIN_DIR)/download
CACHE_DIR := $(shell pwd)/cache

HELM_VERSION := 3.14.3
JQ_VERSION := 1.7.1
KIND_VERSION := 0.22.0
KUBECTL_VERSION := 1.29.3
KUSTOMIZE_VERSION := 5.3.0
YQ_VERSION := 4.43.1

# Test tools
CUSTOMCHECKER := $(TOOLS_DIR)/custom-checker
HELM_BINARY := $(TOOLS_DIR)/helm
HELM := $(HELM_BINARY) --repository-cache $(CACHE_DIR)/helm/repository --repository-config $(CACHE_DIR)/helm/repositories.yaml
JQ := $(TOOLS_DIR)/jq
KIND := $(TOOLS_DIR)/kind
KUBECTL := $(TOOLS_DIR)/kubectl
KUSTOMIZE := $(TOOLS_DIR)/kustomize
STATICCHECK := $(TOOLS_DIR)/staticcheck
YQ := $(TOOLS_DIR)/yq

.PHONY: all
all: help

##@ Basic

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: setup
setup: $(CUSTOMCHECKER) $(HELM_BINARY) $(KIND) $(JQ) $(KUBECTL) $(KUSTOMIZE) $(STATICCHECK) $(YQ) ## Install necessary tools
	$(HELM) repo add cilium https://helm.cilium.io/
	$(HELM) repo update cilium

$(CUSTOMCHECKER):
	GOBIN=$(TOOLS_DIR) go install github.com/cybozu-go/golang-custom-analyzer/cmd/custom-checker@latest

$(HELM_BINARY):
	mkdir -p $(TOOLS_DIR)
	wget -qO - https://get.helm.sh/helm-v$(HELM_VERSION)-linux-amd64.tar.gz | tar zx -O linux-amd64/helm > $@
	chmod +x $@

$(JQ):
	mkdir -p $(TOOLS_DIR)
	wget -qO $@ https://github.com/jqlang/jq/releases/download/jq-$(JQ_VERSION)/jq-linux-amd64
	chmod +x $@

$(KIND):
	GOBIN=$(TOOLS_DIR) go install sigs.k8s.io/kind@v$(KIND_VERSION)

$(KUBECTL):
	mkdir -p $(TOOLS_DIR)
	wget -qO $@ https://storage.googleapis.com/kubernetes-release/release/v$(KUBECTL_VERSION)/bin/linux/amd64/kubectl
	chmod +x $@

$(KUSTOMIZE):
	mkdir -p $(TOOLS_DIR)
	wget -qO - https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv$(KUSTOMIZE_VERSION)/kustomize_v$(KUSTOMIZE_VERSION)_linux_amd64.tar.gz | tar zx -O kustomize > $@
	chmod +x $@

$(STATICCHECK):
	GOBIN=$(TOOLS_DIR) go install honnef.co/go/tools/cmd/staticcheck@latest

$(YQ):
	mkdir -p $(TOOLS_DIR)
	wget -qO $@ https://github.com/mikefarah/yq/releases/download/v$(YQ_VERSION)/yq_linux_amd64
	chmod +x $@

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -rf $(CACHE_DIR)

##@ Development

.PHONY: build
build: ## Build cilium-policy-viewer
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/cilium-policy main.go

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
