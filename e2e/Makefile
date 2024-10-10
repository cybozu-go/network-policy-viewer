CILIUM_VERSION := $(shell go list -m -f '{{.Version}}' github.com/cilium/cilium | cut -c2-)

BIN_DIR := $(shell pwd)/../bin
TOOLS_DIR := $(BIN_DIR)/download
CACHE_DIR := $(shell pwd)/../cache

POLICY_VIEWER := $(BIN_DIR)/npv
HELM := helm --repository-cache $(CACHE_DIR)/helm/repository --repository-config $(CACHE_DIR)/helm/repositories.yaml

##@ Basic

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Test

.PHONY: wait-for-workloads
wait-for-workloads:
	kubectl wait --for=condition=Available --all deployments --all-namespaces --timeout=1h
	kubectl wait --for=condition=Ready --all pods --all-namespaces --timeout=1h

.PHONY: start
start:
	docker pull quay.io/cilium/cilium:v$(CILIUM_VERSION)
	kind create cluster --config testdata/cluster.yaml
	kind load docker-image quay.io/cilium/cilium:v$(CILIUM_VERSION)
	$(HELM) install cilium cilium/cilium --version $(CILIUM_VERSION) \
		--namespace kube-system \
		--set image.pullPolicy=IfNotPresent \
		--set ipam.mode=kubernetes
	kustomize build testdata | kubectl apply -f -
	$(MAKE) --no-print-directory wait-for-workloads

run-test-pod-%:
	cat testdata/template/ubuntu.yaml | \
		yq '.metadata.name = "$*"' | \
		yq '.spec.selector.matchLabels = {"test": "$*"}' | \
		yq '.spec.template.metadata.labels = {"test": "$*"}' | \
		kubectl apply -f -

.PHONY: install-test-pod
install-test-pod:
	$(MAKE) --no-print-directory run-test-pod-self
	$(MAKE) --no-print-directory run-test-pod-l3-ingress-explicit-allow
	$(MAKE) --no-print-directory run-test-pod-l3-ingress-no-rule
	$(MAKE) --no-print-directory run-test-pod-l3-ingress-explicit-deny
	$(MAKE) --no-print-directory run-test-pod-l3-egress-implicit-deny
	$(MAKE) --no-print-directory run-test-pod-l3-egress-explicit-deny
	$(MAKE) --no-print-directory wait-for-workloads
	kubectl apply -f testdata/policy/l3.yaml

.PHONY: install-policy-viewer
install-policy-viewer:
	$(MAKE) -C ../ build
	PODNAME=$$(kubectl get po -l app=ubuntu -o name | cut -d'/' -f2); \
	kubectl cp $(POLICY_VIEWER) $${PODNAME}:/tmp/; \
	kubectl exec $${PODNAME} -- chmod +x /tmp/npv

.PHONY: test
test:
	go test -v -race . -ginkgo.v -ginkgo.fail-fast

.PHONY: stop
stop:
	kind delete cluster
