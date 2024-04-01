CILIUM_VERSION := 1.15.3

BIN_DIR := $(shell pwd)/../bin
TOOLS_DIR := $(BIN_DIR)/download
CILIUM_POLICY := $(BIN_DIR)/cilium-policy
HELM := $(TOOLS_DIR)/helm
KIND := $(TOOLS_DIR)/kind
KUBECTL := $(TOOLS_DIR)/kubectl
KUSTOMIZE := $(TOOLS_DIR)/kustomize

##@ Basic

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Test

.PHONY: start
start:
	docker pull quay.io/cilium/cilium:v$(CILIUM_VERSION)
	$(KIND) create cluster --config cluster.yaml
	$(KIND) load docker-image quay.io/cilium/cilium:v$(CILIUM_VERSION)
	$(HELM) install cilium cilium/cilium --version $(CILIUM_VERSION) \
		--namespace kube-system \
		--set image.pullPolicy=IfNotPresent \
		--set ipam.mode=kubernetes
	$(KUSTOMIZE) build . | $(KUBECTL) apply -f -
	$(KUBECTL) wait --for=condition=Available --all deployments --all-namespaces --timeout=1h
	$(KUBECTL) wait --for=condition=Ready --all pods --all-namespaces --timeout=1h

.PHONY: install
install:
	$(MAKE) -C ../ build
	PODNAME=$$($(KUBECTL) get po -l app=ubuntu -o name | cut -d'/' -f2); \
	$(KUBECTL) cp $(CILIUM_POLICY) $${PODNAME}:/tmp/; \
	$(KUBECTL) exec $${PODNAME} -- chmod +x /tmp/cilium-policy

.PHONY: stop
stop:
	$(KIND) delete cluster
