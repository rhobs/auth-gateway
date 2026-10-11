.PHONY: check-tools kind-tool setup setup-internal cmctl e2e-compile test

CLUSTER_NAME ?= auth-gateway-e2e
KIND_NODE_IMAGE ?= kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a
HTTPBIN_IMAGE ?= ghcr.io/mccutchen/go-httpbin:2.25.0
CERT_MANAGER_VERSION ?= v1.18.2
CERT_MANAGER_CONTROLLER_IMAGE ?= quay.io/jetstack/cert-manager-controller:$(CERT_MANAGER_VERSION)
CERT_MANAGER_CAINJECTOR_IMAGE ?= quay.io/jetstack/cert-manager-cainjector:$(CERT_MANAGER_VERSION)
CERT_MANAGER_WEBHOOK_IMAGE ?= quay.io/jetstack/cert-manager-webhook:$(CERT_MANAGER_VERSION)
CERT_MANAGER_MANIFEST ?= https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml
CMCTL_BIN ?= $(CURDIR)/tools/cmctl
KIND_TOOL := go -C tools tool kind
CERT_MANAGER_MANIFEST_ARG = $(if $(filter http://% https://%,$(CERT_MANAGER_MANIFEST)),$(CERT_MANAGER_MANIFEST),$(abspath $(CERT_MANAGER_MANIFEST)))
GINKGO_ARGS ?=
GINKGO_PROCS ?= 2
PYTHON ?= python3
E2E_RUN_ID ?= r$(shell od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
E2E_RUN_ID := $(E2E_RUN_ID)

REPOSITORY_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
TIMING_SCRIPT := $(REPOSITORY_ROOT)/scripts/time-command.py
REPORT_DIR := .state/reports/$(E2E_RUN_ID)
TIMINGS_FILE := $(REPORT_DIR)/timings.json
E2E_TEST_BIN := .state/bin/$(E2E_RUN_ID)/auth-gateway.test
IMAGE_DEFAULTS := $(shell $(PYTHON) "$(TIMING_SCRIPT)" --timings-file "$(TIMINGS_FILE)" --stage image-defaults --capture-output -- go -C "$(REPOSITORY_ROOT)" run ./cmd/playground-generate -print-image-defaults)
ENVOY_IMAGE ?= $(word 1,$(IMAGE_DEFAULTS))
OTEL_COLLECTOR_IMAGE ?= $(word 2,$(IMAGE_DEFAULTS))

ifneq ($(words $(IMAGE_DEFAULTS)),2)
$(error failed to generate default container image references)
endif

check-tools:
	@set -eu; \
	for tool in docker go '$(PYTHON)'; do \
		command -v "$$tool" >/dev/null || { echo "$$tool is required" >&2; exit 1; }; \
	done
	@docker info >/dev/null

kind-tool:
	$(KIND_TOOL) version >/dev/null

setup:
	$(PYTHON) "$(TIMING_SCRIPT)" --timings-file "$(TIMINGS_FILE)" --stage cluster-setup -- $(MAKE) --no-print-directory setup-internal 'E2E_RUN_ID=$(E2E_RUN_ID)' 'IMAGE_DEFAULTS=$(IMAGE_DEFAULTS)' 'ENVOY_IMAGE=$(ENVOY_IMAGE)' 'OTEL_COLLECTOR_IMAGE=$(OTEL_COLLECTOR_IMAGE)'

setup-internal: check-tools kind-tool
	@set -eu; \
	mkdir -p .state; \
	lock='.state/cluster-$(CLUSTER_NAME).lock'; \
	until mkdir "$$lock" 2>/dev/null; do sleep 1; done; \
	trap 'rmdir "$$lock"' EXIT; \
	clusters=$$($(KIND_TOOL) get clusters); \
	if printf '%s\n' "$$clusters" | grep -qx '$(CLUSTER_NAME)'; then \
		$(KIND_TOOL) export kubeconfig --name '$(CLUSTER_NAME)'; \
	else \
		$(KIND_TOOL) create cluster --name '$(CLUSTER_NAME)' --image '$(KIND_NODE_IMAGE)' --wait 180s; \
		$(KIND_TOOL) export kubeconfig --name '$(CLUSTER_NAME)'; \
	fi
	docker pull '$(ENVOY_IMAGE)'
	docker pull '$(HTTPBIN_IMAGE)'
	docker pull '$(OTEL_COLLECTOR_IMAGE)'
	docker pull '$(CERT_MANAGER_CONTROLLER_IMAGE)'
	docker pull '$(CERT_MANAGER_CAINJECTOR_IMAGE)'
	docker pull '$(CERT_MANAGER_WEBHOOK_IMAGE)'
	@set -eu; \
	lock='.state/cluster-$(CLUSTER_NAME).lock'; \
	until mkdir "$$lock" 2>/dev/null; do sleep 1; done; \
	trap 'rmdir "$$lock"' EXIT; \
	$(KIND_TOOL) load docker-image --name '$(CLUSTER_NAME)' '$(ENVOY_IMAGE)' '$(HTTPBIN_IMAGE)' '$(OTEL_COLLECTOR_IMAGE)' '$(CERT_MANAGER_CONTROLLER_IMAGE)' '$(CERT_MANAGER_CAINJECTOR_IMAGE)' '$(CERT_MANAGER_WEBHOOK_IMAGE)'

cmctl:
	$(PYTHON) "$(TIMING_SCRIPT)" --timings-file "$(TIMINGS_FILE)" --stage cmctl -- sh -c 'go -C tools tool cmctl --help >/dev/null'

test: cmctl setup
	$(PYTHON) "$(TIMING_SCRIPT)" --timings-file "$(TIMINGS_FILE)" --stage framework-test -- go -C .. test -tags=e2e ./e2e/internal/framework
	@mkdir -p "$(dir $(E2E_TEST_BIN))"
	$(PYTHON) "$(TIMING_SCRIPT)" --timings-file "$(TIMINGS_FILE)" --stage e2e-compile -- go -C .. test -tags=e2e -c -o "e2e/$(E2E_TEST_BIN)" ./e2e
	@set -eu; \
	trap 'rm -rf "$(dir $(E2E_TEST_BIN))"' EXIT; \
	$(PYTHON) "$(TIMING_SCRIPT)" --timings-file "$(TIMINGS_FILE)" --stage ginkgo-cli -- env \
		AUTH_GATEWAY_E2E_CONTEXT='kind-$(CLUSTER_NAME)' \
		AUTH_GATEWAY_E2E_RUN_ID='$(E2E_RUN_ID)' \
		AUTH_GATEWAY_E2E_CMCTL='$(abspath $(CMCTL_BIN))' \
		AUTH_GATEWAY_E2E_CERT_MANAGER_MANIFEST='$(CERT_MANAGER_MANIFEST_ARG)' \
		go -C .. tool ginkgo --procs='$(GINKGO_PROCS)' --timeout=30m --no-color \
		--output-dir='e2e/$(REPORT_DIR)' --json-report=auth-gateway.json \
		$(GINKGO_ARGS) 'e2e/$(E2E_TEST_BIN)'

e2e-compile:
	@mkdir -p "$(dir $(E2E_TEST_BIN))"
	$(PYTHON) "$(TIMING_SCRIPT)" --timings-file "$(TIMINGS_FILE)" --stage e2e-compile -- go -C .. test -tags=e2e -c -o "e2e/$(E2E_TEST_BIN)" ./e2e
