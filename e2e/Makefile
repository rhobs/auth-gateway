.PHONY: check-tools setup cmctl test

CLUSTER_NAME ?= auth-gateway-e2e
KIND_NODE_IMAGE ?= kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a
ENVOY_IMAGE ?= envoyproxy/envoy:v1.39.1
HTTPBIN_IMAGE ?= ghcr.io/mccutchen/go-httpbin:2.25.0
OTEL_COLLECTOR_IMAGE ?= otel/opentelemetry-collector-contrib:0.135.0
CERT_MANAGER_VERSION ?= v1.18.2
CERT_MANAGER_CONTROLLER_IMAGE ?= quay.io/jetstack/cert-manager-controller:$(CERT_MANAGER_VERSION)
CERT_MANAGER_CAINJECTOR_IMAGE ?= quay.io/jetstack/cert-manager-cainjector:$(CERT_MANAGER_VERSION)
CERT_MANAGER_WEBHOOK_IMAGE ?= quay.io/jetstack/cert-manager-webhook:$(CERT_MANAGER_VERSION)
CERT_MANAGER_MANIFEST ?= https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml
CMCTL_VERSION ?= v2.6.1
CMCTL_OS ?= $(shell go env GOOS)
CMCTL_ARCH ?= $(shell go env GOARCH)
CMCTL_SUFFIX = $(if $(filter windows,$(CMCTL_OS)),.exe,)
CMCTL_BIN ?= $(CURDIR)/.bin/cmctl-$(CMCTL_VERSION)$(CMCTL_SUFFIX)
CMCTL_ASSET = cmctl_$(CMCTL_OS)_$(CMCTL_ARCH)$(CMCTL_SUFFIX)

check-tools:
	@set -eu; \
	for tool in docker kind kubectl go curl; do \
		command -v "$$tool" >/dev/null || { echo "$$tool is required" >&2; exit 1; }; \
	done
	@docker info >/dev/null

setup: check-tools
	@set -eu; \
	clusters=$$(kind get clusters); \
	if printf '%s\n' "$$clusters" | grep -qx '$(CLUSTER_NAME)'; then \
		kind export kubeconfig --name '$(CLUSTER_NAME)'; \
	else \
		kind create cluster --name '$(CLUSTER_NAME)' --image '$(KIND_NODE_IMAGE)' --wait 180s; \
	fi
	docker pull '$(ENVOY_IMAGE)'
	docker pull '$(HTTPBIN_IMAGE)'
	docker pull '$(OTEL_COLLECTOR_IMAGE)'
	docker pull '$(CERT_MANAGER_CONTROLLER_IMAGE)'
	docker pull '$(CERT_MANAGER_CAINJECTOR_IMAGE)'
	docker pull '$(CERT_MANAGER_WEBHOOK_IMAGE)'
	kind load docker-image --name '$(CLUSTER_NAME)' '$(ENVOY_IMAGE)' '$(HTTPBIN_IMAGE)' '$(OTEL_COLLECTOR_IMAGE)' '$(CERT_MANAGER_CONTROLLER_IMAGE)' '$(CERT_MANAGER_CAINJECTOR_IMAGE)' '$(CERT_MANAGER_WEBHOOK_IMAGE)'
	kubectl --context 'kind-$(CLUSTER_NAME)' apply --validate=false -f '$(CERT_MANAGER_MANIFEST)'
	@set -eu; \
	for cm_deployment in cert-manager cert-manager-cainjector cert-manager-webhook; do \
		kubectl --context 'kind-$(CLUSTER_NAME)' --namespace cert-manager rollout status "deployment/$$cm_deployment" --timeout=240s; \
	done

cmctl:
	@set -eu; \
	if [ ! -x '$(CMCTL_BIN)' ]; then \
		mkdir -p '$(dir $(CMCTL_BIN))'; \
		curl -fsSL 'https://github.com/cert-manager/cmctl/releases/download/$(CMCTL_VERSION)/$(CMCTL_ASSET)' -o '$(CMCTL_BIN)'; \
		chmod +x '$(CMCTL_BIN)'; \
	fi

test: setup cmctl
	cd .. && AUTH_GATEWAY_E2E_CONTEXT='kind-$(CLUSTER_NAME)' AUTH_GATEWAY_E2E_CMCTL='$(abspath $(CMCTL_BIN))' go test -tags=e2e -count=1 -v ./e2e
