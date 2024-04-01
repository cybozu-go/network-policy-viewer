BIN_DIR := $(shell pwd)/bin
TOOLS_DIR := $(BIN_DIR)/download
HELM_VERSION := 3.14.3
KIND_VERSION := 0.22.0
KUBECTL_VERSION := 1.29.3
KUSTOMIZE_VERSION := 5.3.0

# Test tools
HELM := $(TOOLS_DIR)/helm
KUBECTL := $(TOOLS_DIR)/kubectl
KUSTOMIZE := $(TOOLS_DIR)/kustomize
STATICCHECK := $(TOOLS_DIR)/staticcheck

.PHONY: all
all: help

##@ Basic

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: setup
setup: $(HELM) $(KUBECTL) $(KUSTOMIZE) ## Install necessary tools
	GOBIN=$(TOOLS_DIR) go install sigs.k8s.io/kind@v$(KIND_VERSION)
	$(HELM) repo add cilium https://helm.cilium.io/
	$(HELM) repo update cilium

$(HELM):
	mkdir -p $(TOOLS_DIR)
	wget -qO - https://get.helm.sh/helm-v$(HELM_VERSION)-linux-amd64.tar.gz | tar zx -O linux-amd64/helm > $@
	chmod +x $@

$(KUBECTL):
	mkdir -p $(TOOLS_DIR)
	wget -qO $@ https://storage.googleapis.com/kubernetes-release/release/v$(KUBECTL_VERSION)/bin/linux/amd64/kubectl
	chmod +x $@

$(KUSTOMIZE):
	mkdir -p $(TOOLS_DIR)
	wget -qO - https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv$(KUSTOMIZE_VERSION)/kustomize_v$(KUSTOMIZE_VERSION)_linux_amd64.tar.gz | tar zx -O kustomize > $@
	chmod +x $@

.PHONY: build
build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/cilium-policy main.go

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

.PHONY: test
test:
	if find . -name go.mod | grep -q go.mod; then \
		$(MAKE) test-go; \
	fi
