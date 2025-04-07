CILIUM_VERSION := $(shell go list -m -f '{{.Version}}' github.com/cilium/cilium | cut -c2-)

BIN_DIR := $(shell pwd)/../bin
TOOLS_DIR := $(BIN_DIR)/download
CACHE_DIR := $(shell pwd)/../cache

POLICY_VIEWER := $(BIN_DIR)/npv
HELM := helm --repository-cache $(CACHE_DIR)/helm/repository --repository-config $(CACHE_DIR)/helm/repositories.yaml

DEPLOYMENT_REPLICAS ?= 1

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

	cd ..; docker build . -t cilium-agent-proxy:dev
	kind load docker-image cilium-agent-proxy:dev

	kustomize build testdata | kubectl apply -f -
	$(MAKE) --no-print-directory wait-for-workloads

run-test-pod-%:
	@# https://github.com/orgs/aquaproj/discussions/2964
	@echo Hello | yq > /dev/null
	cat testdata/template/testhttpd.yaml | \
		yq '.metadata.name = "$*"' | \
		yq '.spec.replicas = $(DEPLOYMENT_REPLICAS)' | \
		yq '.spec.selector.matchLabels = {"test": "$*"}' | \
		yq '.spec.template.metadata.labels = {"test": "$*", "group": "test"}' | \
		kubectl apply -f -

run-ubuntu-pod-%:
	@# https://github.com/orgs/aquaproj/discussions/2964
	@echo Hello | yq > /dev/null
	cat testdata/template/ubuntu.yaml | \
		yq '.metadata.name = "$*"' | \
		yq '.spec.replicas = $(DEPLOYMENT_REPLICAS)' | \
		yq '.spec.selector.matchLabels = {"test": "$*"}' | \
		yq '.spec.template.metadata.labels = {"test": "$*", "group": "test"}' | \
		kubectl apply -f -

.PHONY: install-test-pod
install-test-pod:
	$(MAKE) --no-print-directory run-ubuntu-pod-self
	$(MAKE) --no-print-directory run-test-pod-l3-ingress-explicit-allow-all
	$(MAKE) --no-print-directory run-test-pod-l3-ingress-implicit-deny-all
	$(MAKE) --no-print-directory run-test-pod-l3-ingress-explicit-deny-all
	$(MAKE) --no-print-directory run-test-pod-l3-egress-implicit-deny-all
	$(MAKE) --no-print-directory run-test-pod-l3-egress-explicit-deny-all

	$(MAKE) --no-print-directory run-test-pod-l4-ingress-explicit-allow-any
	$(MAKE) --no-print-directory run-test-pod-l4-ingress-explicit-allow-tcp
	$(MAKE) --no-print-directory run-test-pod-l4-ingress-explicit-deny-any
	$(MAKE) --no-print-directory run-test-pod-l4-ingress-explicit-deny-udp
	$(MAKE) --no-print-directory run-test-pod-l4-egress-explicit-deny-any
	$(MAKE) --no-print-directory run-test-pod-l4-egress-explicit-deny-tcp
	$(MAKE) --no-print-directory run-test-pod-l4-ingress-all-allow-tcp
	$(MAKE) --no-print-directory wait-for-workloads

	# Cilium-agents on different nodes may simultaneously create multiple CiliumIdentities for a same set of labels.
	# To enforce the following test deployment to use a same CiliumIdentity, we first create it with replicas=1 and then upscale.
	$(MAKE) --no-print-directory DEPLOYMENT_REPLICAS=2 run-test-pod-l3-ingress-explicit-allow-all
	$(MAKE) --no-print-directory wait-for-workloads

	kubectl apply -f testdata/policy/l3.yaml
	kubectl apply -f testdata/policy/l4.yaml

.PHONY: install-policy-viewer
install-policy-viewer:
	$(MAKE) -C ../ build
	PODNAME=$$(kubectl get po -l app=ubuntu -o name | cut -d'/' -f2); \
	kubectl cp testdata/onboard $${PODNAME}:/tmp/; \
	kubectl exec $${PODNAME} -- chmod +x /tmp/onboard; \
	kubectl exec $${PODNAME} -- /tmp/onboard; \
	kubectl cp $(POLICY_VIEWER) $${PODNAME}:/tmp/; \
	kubectl exec $${PODNAME} -- chmod +x /tmp/npv; \
	kubectl cp $$(aqua which kubectl) $${PODNAME}:/tmp/; \
	kubectl exec $${PODNAME} -- chmod +x /tmp/kubectl

.PHONY: pilot
pilot:
	@PODNAME=$$(kubectl get po -l app=ubuntu -o name | cut -d'/' -f2); \
	kubectl exec -it $${PODNAME} -- bash

.PHONY: test
test:
	go test -v -race . -ginkgo.v -ginkgo.fail-fast

.PHONY: stop
stop:
	kind delete cluster
