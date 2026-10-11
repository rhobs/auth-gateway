.PHONY: check-tools setup cmctl test

CLUSTER_NAME ?= auth-gateway-e2e
KIND_NODE_IMAGE ?= kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a
HTTPBIN_IMAGE ?= ghcr.io/mccutchen/go-httpbin:2.25.0
ROLLOUT_PROBE_IMAGE ?= curlimages/curl:8.12.1
CERT_MANAGER_VERSION ?= v1.18.2
CERT_MANAGER_CONTROLLER_IMAGE ?= quay.io/jetstack/cert-manager-controller:$(CERT_MANAGER_VERSION)
CERT_MANAGER_CAINJECTOR_IMAGE ?= quay.io/jetstack/cert-manager-cainjector:$(CERT_MANAGER_VERSION)
CERT_MANAGER_WEBHOOK_IMAGE ?= quay.io/jetstack/cert-manager-webhook:$(CERT_MANAGER_VERSION)
CERT_MANAGER_MANIFEST ?= https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml
CMCTL_BIN ?= $(CURDIR)/tools/cmctl
CERT_MANAGER_MANIFEST_ARG = $(if $(filter http://% https://%,$(CERT_MANAGER_MANIFEST)),$(CERT_MANAGER_MANIFEST),$(abspath $(CERT_MANAGER_MANIFEST)))
GINKGO_ARGS ?=
GINKGO_PROCS ?= 2
E2E_RUN_ID ?= r$(shell od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
E2E_RUN_ID := $(E2E_RUN_ID)

REPOSITORY_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
IMAGE_DEFAULTS := $(shell go -C "$(REPOSITORY_ROOT)" run ./cmd/playground-generate -print-image-defaults)
ENVOY_IMAGE ?= $(word 1,$(IMAGE_DEFAULTS))
OTEL_COLLECTOR_IMAGE ?= $(word 2,$(IMAGE_DEFAULTS))

check-tools:
	@set -eu; \
	for tool in docker kind go; do \
		command -v "$$tool" >/dev/null || { echo "$$tool is required" >&2; exit 1; }; \
	done
	@docker info >/dev/null

setup: check-tools
	@set -eu; \
	mkdir -p .state; \
	lock='.state/cluster-$(CLUSTER_NAME).lock'; \
	until mkdir "$$lock" 2>/dev/null; do sleep 1; done; \
	trap 'rmdir "$$lock"' EXIT; \
	clusters=$$(kind get clusters); \
	if printf '%s\n' "$$clusters" | grep -qx '$(CLUSTER_NAME)'; then \
		kind export kubeconfig --name '$(CLUSTER_NAME)'; \
	else \
		kind create cluster --name '$(CLUSTER_NAME)' --image '$(KIND_NODE_IMAGE)' --wait 180s; \
		kind export kubeconfig --name '$(CLUSTER_NAME)'; \
	fi
	docker pull '$(ENVOY_IMAGE)'
	docker pull '$(HTTPBIN_IMAGE)'
	docker pull '$(ROLLOUT_PROBE_IMAGE)'
	docker pull '$(OTEL_COLLECTOR_IMAGE)'
	docker pull '$(CERT_MANAGER_CONTROLLER_IMAGE)'
	docker pull '$(CERT_MANAGER_CAINJECTOR_IMAGE)'
	docker pull '$(CERT_MANAGER_WEBHOOK_IMAGE)'
	@set -eu; \
	lock='.state/cluster-$(CLUSTER_NAME).lock'; \
	until mkdir "$$lock" 2>/dev/null; do sleep 1; done; \
	trap 'rmdir "$$lock"' EXIT; \
	kind load docker-image --name '$(CLUSTER_NAME)' '$(ENVOY_IMAGE)' '$(HTTPBIN_IMAGE)' '$(ROLLOUT_PROBE_IMAGE)' '$(OTEL_COLLECTOR_IMAGE)' '$(CERT_MANAGER_CONTROLLER_IMAGE)' '$(CERT_MANAGER_CAINJECTOR_IMAGE)' '$(CERT_MANAGER_WEBHOOK_IMAGE)'

cmctl:
	go -C tools tool cmctl --help >/dev/null

test: cmctl setup
	@mkdir -p .state/reports/$(E2E_RUN_ID)
	cd .. && go test -tags=e2e ./e2e/internal/framework
	cd .. && AUTH_GATEWAY_E2E_CONTEXT='kind-$(CLUSTER_NAME)' AUTH_GATEWAY_E2E_RUN_ID='$(E2E_RUN_ID)' AUTH_GATEWAY_E2E_ROLLOUT_PROBE_IMAGE='$(ROLLOUT_PROBE_IMAGE)' AUTH_GATEWAY_E2E_CMCTL='$(abspath $(CMCTL_BIN))' AUTH_GATEWAY_E2E_CERT_MANAGER_MANIFEST='$(CERT_MANAGER_MANIFEST_ARG)' go tool ginkgo --tags=e2e --procs='$(GINKGO_PROCS)' --timeout=30m --no-color --output-dir='e2e/.state/reports/$(E2E_RUN_ID)' --json-report=auth-gateway.json $(GINKGO_ARGS) ./e2e
