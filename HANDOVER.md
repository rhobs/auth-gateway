# Handover: RHOBS-1782

## Goal and rules

- Implement the epic in small, tested steps. This branch covers the bootstrap work for RHOBS-1783.
- Use `/Users/pgough/Desktop/projects/regional-observability-service` as a reference. Port only code needed for the current Jira step.
- Keep docs brief and use simple technical English (STE). Add a handover after each step.
- Commit each tested step on a feature branch. Never push directly to `main`.
- Write commit messages with enough context to explain what changed and why.
- Preserve the existing formatting-only change in the PoC file `service-gateway/README.MD`.
- More cases may be added to the epic. Read Jira again before each new step.
- Start with unit tests and use golden files where they fit before moving on to e2e tests.

## Jira scope

- RHOBS-1782 is the epic, "M2M Authentication Gateway for RHOBS Observability Writers".
- RHOBS-1783 is the bootstrap and developer experience task. It covers the config API, local e2e testing, a pluggable metrics backend, and Kubernetes manifests.
- RHOBS-1784 is the JWT task. It covers multiple issuers, transport modes, tenant mapping, and per-tenant API authorization.
- RHOBS-1783 also mentions authentication policies in its config API. This implementation has no auth policy API. Keep RHOBS-1783 open until this scope is resolved and tested.
- Jira MCP and the `jira` CLI are unavailable in this workspace, so Jira was accessed through the authenticated REST API. RHOBS-1798 is a subtask of RHOBS-1783 for error-only access logging. RHOBS-1799 tracks built-in Prometheus metrics. RHOBS-1801 is a new subtask of RHOBS-1783 for host-scoped HTTP/HTTPS support and cert-manager certificate-rotation coverage.

## Current state

- The target repo is `/Users/pgough/Desktop/projects/rosa/auth-gateway`. The implementation branch is `rhobs-1783-bootstrap`; local `main` is the integration target.
- This is a progress step. It does not complete or close RHOBS-1783.
- The `config` package loads one strict YAML document, applies defaults, validates it, and generates Envoy config and Kubernetes resources.
- The listener supports exact HTTP and HTTPS host groups on one Envoy port. If both groups are omitted, existing configs keep wildcard HTTP. HTTPS uses a server-only TLS context, file-based SDS, and a Kubernetes TLS Secret; the client certificate is not required. The HTTP and HTTPS host groups currently expose the same routes.
- The generated HTTP connection manager writes structured JSON access logs to stdout for HTTP status codes of 400 or higher. RHOBS-1798 tracks this work.
- Each API has one upstream and must define one or more `routes`. Each route must list one or more supported HTTP methods and select exactly one exact path, prefix, or safe RE2 regex match. Missing or empty method lists are configuration errors. An optional path, prefix, or regex rewrite transforms the request path. The former `method`, `path`, and `upstream.path` fields are not supported.
- Envoy checks routes in declaration order, returns 405 with an `Allow` header for a matched path with the wrong method, and returns 404 for unknown paths.
- Kubernetes output includes Envoy and collector ConfigMaps, a ServiceAccount, a Deployment, and one Service with HTTP, optional HTTPS, and metrics ports. HTTP and HTTPS target the same Envoy listener. Envoy runs as UID and GID 101. The Envoy image entrypoint fails when it runs as root.
- The Deployment includes an OpenTelemetry Collector sidecar. It scrapes Envoy's loopback `/stats/prometheus` endpoint on port 9901 every 30 seconds and exposes Prometheus metrics on port 8889. The scrape path is fixed in the generated Collector config. The image is configurable with `kubernetes.otel_collector_image` and defaults to `otel/opentelemetry-collector-contrib:0.135.0`.
- The local Kind e2e fixture uses the route-list format with separate HTTP and HTTPS hosts. The test checks existing request routing and metrics, host isolation between protocols, certificate trust, and cert-manager server-certificate renewal through Secret projection and Envoy SDS. It invokes `cmctl renew` through the framework, then verifies Envoy serves the replacement certificate without a pod restart. It uses Envoy 1.39.1, HTTPBin 2.25.0, the OpenTelemetry Collector 0.135.0, and cert-manager 1.18.2. The test removes its namespace when it ends; cert-manager remains installed in the reusable Kind cluster.
- The local e2e suite uses Ginkgo and Gomega. Suite hooks apply shared fixtures, manage cleanup, and collect failure diagnostics. Route cases, HTTPS host isolation, certificate rotation, and metrics run as named specs; Gomega `Eventually` handles readiness and rotation polling.
- `e2e/internal/framework` uses client-go with the configured kubeconfig context for server-side manifest apply, namespace lifecycle, readiness checks, Secret and Pod reads, diagnostics, and loopback port forwarding. The suite installs cert-manager through the framework's `BeforeSuite` hook and waits for its Deployments. The framework wraps `cmctl renew` for certificate rotation. The Makefile downloads cmctl v2.6.1 and writes a Ginkgo JSON report under `.state/reports`. `certificates.yaml` remains the cert-manager fixture applied during suite setup.
- Config tests load the default, route-list, and TLS YAML examples from `config/testdata`. TLS ConfigMap and Deployment output are checked against goldens, including Envoy's file-based SDS configuration and the projected Secret mount.
- The PoC's JWT, mTLS, SPIFFE, tenant policy, and other gateway features were not ported.
- The HTTP/HTTPS bootstrap and certificate-rotation implementation is committed as `898449f` on `rhobs-1783-bootstrap`.

## Checks

These checks passed for the bootstrap implementation before the route-list update:

- `make -C e2e test`
- `go mod tidy -diff`

For the route-list implementation, `make test` passes with tests for defaults, validation, Envoy matchers, rewrites, and 405/404 responses. `go vet ./...` passes. `go test -tags=e2e -run '^$' ./e2e` compiles the e2e test without running it. The Kind e2e test was not run after the route-list update. `git diff --check` passes for the current changes.

The test fixture extraction was formatted with `gofmt` and checked with `git diff --check`. Tests were not run for that change.

For the error-only access logging step, `gofmt` and `git diff --check` were run. Go tests were not run.

For the mandatory route-method change, `gofmt` and `git diff --check` were run. Go tests were not run.

For built-in Prometheus metrics, `gofmt`, `make test`, `go vet ./...`, `go test -tags=e2e -run '^$' ./e2e`, `make -C e2e test`, and `git diff --check` pass. The generated collector config uses a 30-second scrape interval. The Kind e2e test verifies that the existing Service exposes scraped Envoy metrics on port 8889.

For the original HTTP/HTTPS listener bootstrap, `go test ./...`, `go vet ./...`, `go test -tags=e2e -run '^$' ./e2e`, `go mod tidy -diff`, `make -C e2e test`, and `git diff --check` pass. At that stage, the Kind test used `cmctl renew` to force certificate issuance, then verified a new certificate and public key were served over HTTPS while the Envoy pod UID stayed the same.

For the initial Ginkgo and client-go e2e framework, `gofmt`, `go mod tidy -diff`, `go test ./...`, `go test -tags=e2e -run '^$' ./e2e ./e2e/cmd/setup-cert-manager`, `go test -tags=e2e ./e2e/internal/framework`, `go vet -tags=e2e ./e2e ./e2e/cmd/setup-cert-manager`, `go tool ginkgo --tags=e2e --dry-run --no-color ./e2e`, `make -C e2e test`, and `git diff --check` pass. The dry run confirms the seven registered specs without setting up Kind. The live Kind suite passed all seven specs. Client-go handles Kubernetes operations, manifest apply, and port forwarding, so `kubectl` is no longer required by the e2e workflow.

RHOBS-1801 was created under RHOBS-1783 with status To Do. It describes the exact-host HTTP/HTTPS listener bootstrap, server-only TLS from a Kubernetes Secret, and the certificate-rotation e2e test.

For the e2e framework cleanup, cert-manager installation moved from `e2e/cmd/setup-cert-manager` into `Environment.EnsureCertManager`, called by the Ginkgo `BeforeSuite`. This removes a one-off command and keeps cluster setup alongside the framework's other Kubernetes lifecycle operations. Renewal uses the pinned `cmctl renew` command through the framework; the suite does not duplicate cmctl's certificate status behavior in a unit test. `gofmt`, `go mod tidy -diff`, `go test ./...`, `go vet ./...`, `go test -tags=e2e -run '^$' ./e2e ./e2e/internal/framework`, `go vet -tags=e2e ./e2e ./e2e/internal/framework`, `go tool ginkgo --tags=e2e --dry-run --no-color ./e2e`, and `git diff --check` pass. `make -C e2e test` passes all seven specs against the reusable Kind cluster, including cert-manager installation from `BeforeSuite` and certificate rotation without a gateway pod restart.

The e2e test needs Docker, Kind, Go, curl, and network access. It creates or reuses the `auth-gateway-e2e` Kind cluster and loads the pinned images. The Ginkgo suite installs the pinned cert-manager manifest and deletes only the `auth-gateway-e2e` namespace.

## Next step

Resolve the authentication-policy API requirement in RHOBS-1783 before closing that task. Keep JWT work under RHOBS-1784 and port only the code needed for its accepted cases.
