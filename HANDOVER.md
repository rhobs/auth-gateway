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
- Keep tests focused and high-value. Each test should cover a distinct behavior; avoid redundant cases that exercise the same behavior through another layer or differ only in equivalent input forms.
- Organize e2e coverage by use case. Combine related behaviors that need the same configuration and resources (for example, server TLS host handling and automatic certificate reload) in one Ginkgo `Ordered` container. Give each container its own namespace, provision it in `BeforeAll`, and remove it with `DeferCleanup`. Keep namespace-scoped resources and diagnostics within that container so Ginkgo can run independent containers on separate processes. Add a label for each use case.
- Keep reusable Kubernetes lifecycle operations, port forwarding, and runtime diagnostics in `e2e/internal/framework`. Keep fixture shaping, protocol-specific clients, and scenario assertions in the e2e test package.

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
- The required `servers` list binds exact DNS hostnames to named APIs on one Envoy port. Each hostname appears once across HTTP and HTTPS. An absent `tls_config` selects HTTP; a non-nil `tls_config` selects HTTPS. Version 1 now rejects `listener.http_hosts`, `listener.https_hosts`, and global `server_tls`. There is no wildcard fallback.
- A server exposes only its `apis` bindings. Missing or empty bindings serve 404 for every path. Unknown or repeated bindings are errors. APIs can be reused across servers or remain unbound. Duplicate path/method matches are rejected within an API and across APIs bound to the same server; separate servers can use the same route.
- Each HTTPS server has its own SNI-selected TLS chain, HTTP authority match, and file-based SDS resource. Servers can use separate Kubernetes TLS Secrets or share a certificate. Paths default to `/etc/<secret>/tls.crt` and `tls.key`; file-only TLS without a Secret retains `/etc/auth-gateway-tls` defaults. Identical Secret/path bindings share a mount; conflicting or overlapping mount directories are rejected. Client certificates are not required.
- `config/testdata/tls.yaml` covers one HTTP and two HTTPS servers, including an empty API binding and distinct Secrets. HTTP and HTTPS share port 8080; the generated Service exposes ports 80 and 443 when those protocols exist. If a proxy terminates caller TLS and forwards plain HTTP, Envoy matches the HTTP `Host`. TLS passthrough or re-encryption must use a configured HTTPS server's SNI hostname.
- The generated HTTP connection manager writes structured JSON access logs to stdout for HTTP status codes of 400 or higher. RHOBS-1798 tracks this work.
- Each API has one upstream and must define one or more `routes`. Each route must list one or more supported HTTP methods and select exactly one exact path, prefix, or safe RE2 regex match. Missing or empty method lists are configuration errors. An optional path, prefix, or regex rewrite transforms the request path. The former `method`, `path`, and `upstream.path` fields are not supported.
- Envoy checks APIs in server binding order, then routes in each API's declaration order. It returns 405 with an `Allow` header only for bound routes with the wrong method, and 404 for unbound or unknown paths.
- Kubernetes output includes Envoy and collector ConfigMaps, a ServiceAccount, a Deployment, and one Service with ports for configured protocols and metrics. HTTP and HTTPS target the same Envoy listener. All generated SDS files are projected into the Envoy container. Envoy runs as UID and GID 101. The Envoy image entrypoint fails when it runs as root.
- The Deployment includes an OpenTelemetry Collector sidecar. It scrapes Envoy's loopback `/stats/prometheus` endpoint on port 9901 every 30 seconds and exposes Prometheus metrics on port 8889. The scrape path is fixed in the generated Collector config. The image is configurable with `kubernetes.otel_collector_image` and defaults to `otel/opentelemetry-collector-contrib:0.135.0`.
- The local Kind fixture defines two HTTP and two HTTPS servers with different API bindings. The Ginkgo suite has HTTP routing/metrics and server TLS groups, each with its own namespace (`auth-gateway-routing-e2e` and `auth-gateway-tls-e2e`). The TLS group checks certificate trust, unknown SNI, mismatched SNI/authority, and API isolation. It renews one of two certificates with `cmctl renew`, then checks that the other certificate and gateway Pod UID stay unchanged. Unknown SNI uses a separate port-forward because the expected TLS reset can close client-go's tunnel. Images remain Envoy 1.39.1, HTTPBin 2.25.0, OpenTelemetry Collector 0.135.0, and cert-manager 1.18.2. Both namespaces are removed at the end; cert-manager remains in the reusable Kind cluster.
- The local e2e suite uses Ginkgo and Gomega. Each use-case group is an `Ordered` container with its own `BeforeAll` setup, fixtures, port forwards, and cleanup. The HTTP group tests routing and metrics; the TLS group also installs cert-manager. Gomega `Eventually` handles readiness, metrics, and certificate rotation polling. The Makefile runs two Ginkgo processes by default; set `GINKGO_PROCS=1` to run serially.
- `e2e/internal/framework` uses client-go with the configured kubeconfig context for server-side manifest apply, namespace lifecycle, readiness checks, Secret and Pod reads, Envoy and Kubernetes diagnostics, and loopback port forwarding. Each Ginkgo process creates its own framework client in `BeforeSuite`. The TLS group installs cert-manager with `Environment.EnsureCertManager` and waits for its Deployments. The framework wraps `cmctl renew` for certificate rotation. The Makefile downloads cmctl v2.6.1 and writes a Ginkgo JSON report under `.state/reports`. `certificates.yaml` remains the cert-manager fixture applied during TLS group setup. Fixture shaping and protocol-specific request helpers remain in `e2e/support_test.go`.
- Config tests load the default, route-list, and TLS fixtures and the root `config.example.yaml`. Tests cover server bindings, route isolation/order, scoped conflicts, TLS defaults, input immutability, and mount conflicts/sharing. TLS ConfigMap and Deployment goldens include multiple SDS files and Secret mounts.
- `docs/tls-secrets.md` describes the Kubernetes Secret projection and Envoy file-based SDS rotation flow, with upstream Envoy and Kubernetes references.
- The PoC's JWT, mTLS, SPIFFE, tenant policy, and other gateway features were not ported.
- `SERVER-CONFIG-PLAN.md` records the approved server migration plan. The README and TLS documentation describe the new format and migration from the old host lists.
- The HTTP/HTTPS bootstrap and certificate-rotation implementation is committed as `898449f` on `rhobs-1783-bootstrap`.
- The e2e framework cleanup and TLS ConfigMap golden are committed as `45af222`; the TLS Deployment golden is committed as `b267dbd` on the same branch.

## Checks

For the server configuration migration (2026-10-02), `make test`, `go vet ./...`, `go test -tags=e2e -run '^$' ./e2e`, `go vet -tags=e2e ./e2e`, and `make -C e2e test` pass. All 11 Kind specs pass across the default two Ginkgo processes. The TLS test verifies strict SNI/authority and API isolation, then renews one certificate through Secret projection and SDS while the other certificate and gateway Pod UID stay unchanged. Goldens were regenerated with `go test ./config -run Golden -update` and reviewed. Modified Go files are formatted and `git diff --check` passes.

Checks used `GOCACHE=/private/tmp/auth-gateway-go-cache` because the default Go build cache was restricted in the agent sandbox. Jira scope was read through the authenticated REST API: RHOBS-1783 still includes an unresolved authentication-policy API requirement, and RHOBS-1801 keeps JWT and client mTLS out of scope. No Jira status was changed.

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

RHOBS-1801 is a To Do subtask of RHOBS-1783, which is linked to epic RHOBS-1782. Its updated title and scope cover host-scoped HTTP/HTTPS and automatic TLS rotation: cert-manager updates the Kubernetes TLS Secret and Envoy reloads the projected files through SDS without a Pod restart. The Kind test uses `cmctl renew` to trigger that path.

For the e2e framework cleanup, cert-manager installation moved from `e2e/cmd/setup-cert-manager` into `Environment.EnsureCertManager`, called by the Ginkgo `BeforeSuite`. This removes a one-off command and keeps cluster setup alongside the framework's other Kubernetes lifecycle operations. Renewal uses the pinned `cmctl renew` command through the framework; the suite does not duplicate cmctl's certificate status behavior in a unit test. `gofmt`, `go mod tidy -diff`, `go test ./...`, `go vet ./...`, `go test -tags=e2e -run '^$' ./e2e ./e2e/internal/framework`, `go vet -tags=e2e ./e2e ./e2e/internal/framework`, `go tool ginkgo --tags=e2e --dry-run --no-color ./e2e`, and `git diff --check` pass. `make -C e2e test` passes all seven specs against the reusable Kind cluster, including cert-manager installation from `BeforeSuite` and certificate rotation without a gateway pod restart.

For the TLS Kubernetes goldens, `go test ./...`, `go vet ./...`, and `git diff --check` pass. The TLS fixture checks both the generated Envoy SDS ConfigMap and the Deployment's read-only Secret volume mount. The golden-only follow-up did not change runtime code.

The e2e test needs Docker, Kind, Go, curl, and network access. It creates or reuses the `auth-gateway-e2e` Kind cluster and loads the pinned images. The TLS group installs the pinned cert-manager manifest. The Ginkgo suite deletes only its `auth-gateway-routing-e2e` and `auth-gateway-tls-e2e` namespaces.

For the e2e suite organization and framework diagnostics, `gofmt` and `git diff --check` pass. The Kind e2e suite was not run after these changes.

## Next step

The server migration and parallel Kind checks are complete. Resolve the authentication-policy API requirement in RHOBS-1783 before closing that task. Keep JWT work under RHOBS-1784. Before adding new behavior, read the relevant Jira scope and add use-case coverage with isolated namespaces and setup.
