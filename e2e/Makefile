.PHONY: check-tools setup test

CLUSTER_NAME ?= auth-gateway-e2e
KIND_NODE_IMAGE ?= kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a
ENVOY_IMAGE ?= envoyproxy/envoy:v1.39.1
HTTPBIN_IMAGE ?= ghcr.io/mccutchen/go-httpbin:2.25.0
OTEL_COLLECTOR_IMAGE ?= otel/opentelemetry-collector-contrib:0.135.0

check-tools:
	@set -eu; \
	for tool in docker kind kubectl go; do \
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
	kind load docker-image --name '$(CLUSTER_NAME)' '$(ENVOY_IMAGE)' '$(HTTPBIN_IMAGE)' '$(OTEL_COLLECTOR_IMAGE)'

test: setup
	cd .. && AUTH_GATEWAY_E2E_CONTEXT='kind-$(CLUSTER_NAME)' go test -tags=e2e -count=1 -v ./e2e
