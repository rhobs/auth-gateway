# Handover: RHOBS-1782

## Production configuration handoff (2026-10-03)

- Implementation is on `production-configuration`, based on `RHOBS-1784` at
  `6d2c389`. No remote push was made.
- The typed API now covers listener/route timeouts, backend TLS/HTTP/2,
  `jwt.jwks`, CA references, overload budgets, workers and metrics.
  Both generators share defaults and timeout resolution. The old `jwks_uri`
  field is rejected. Caller-owned configuration stays unchanged.
- `config.auth.example.yaml` comments out optional defaults. Unit tests check
  defaults, invalid combinations and generated resources.
  `config.production.example.yaml` demonstrates workload-specific overrides.
- Kubernetes output uses the configured Envoy image with a TCP readiness probe
  and the existing 30s termination grace. Static settings and CA
  updates require rollout; mapping-only ECDS and downstream certificate SDS
  reload remain supported. There is still no checksum annotation.
- The added production HTTP/2 and hardening e2e scenarios were removed. Existing
  JWT tests use supported JWKS cache and CA input settings, without rewriting
  generated bootstrap or replacing the system CA mount. Keep the test scope
  below when continuing this work.
- `make update-golden` updates generated references through the config package's
  `go test -update` flag. `make test-runtime` optionally validates generated
  Envoy and Collector configs in their pinned images.

## Test scope

- Gateway e2e tests focus on authentication, authorization, routing and request
  transforms. Use httpbin to verify the method, path, headers and body sent to
  the backend, including credential removal and trusted identity outputs.
- Do not add e2e tests for Envoy's HTTP semantics, such as HTTP/2 flow control,
  timeout enforcement, retries, overload behavior or connection draining. Those
  belong to Envoy's e2e suite, not this gateway's.
- Validate production settings with unit tests for defaults, invalid
  combinations and generated Envoy/Kubernetes configuration. Optional image
  checks may validate generated config.
- Keep existing gateway integration coverage. Any new e2e case needs a distinct
  gateway-owned behavior; production hardening alone is not a reason to add one.
  This scope supersedes the production plan's original runtime-test proposals.
## RHOBS-1784 current handoff (2026-10-03)

- Work is on the `RHOBS-1784` feature branch. The native JWT implementation is
  committed in separate config/runtime, e2e, and documentation batches. Do not
  push to `main`.
- Keep the Envoy filter chain native: `jwt_authn`, RBAC on original claims,
  `set_filter_state`, route-specific required-header RBAC, header mutation, and
  router. Do not restore Lua. Envoy 1.39.1 exposes `envoy.string` filter-state
  values as bytes; unmatched mappings return empty and rely on `skip_if_empty`
  to preserve passthrough. Do not reintroduce `string(bytes)` in CEL.
- When mappings exist, the `set_filter_state` config is a file-based ECDS
  resource in `processing.yaml`, supplied by a separate `<name>-processing`
  ConfigMap mounted at `/etc/auth-gateway/processing`. Mapping updates change
  that ConfigMap only; the bootstrap, Deployment template, and Pod identity stay
  the same. Authorization continues to use the original verified claim.
- There is no generated checksum annotation. Static bootstrap changes still
  need an explicit Deployment rollout to take effect. Keep this behavior visible
  in docs and revisit only if deployment owners want a different rollout
  mechanism.
- mTLS remains future work. Preserve `config.mtls.example.yaml` as an example;
  do not implement mTLS here. Retain coverage for both JWT issuers and their
  server isolation.
- Mapping updates must be tested by applying only the processing ConfigMap,
  checking the changed upstream value, and confirming the Pod UID is unchanged.
  The focused JWT e2e label is `jwt`; the complete e2e suite is also required
  before handoff. Record any local Kind or Docker limitation accurately.

## Goal and rules

- Implement the epic in small, tested steps. This branch contains the completed bootstrap implementation for RHOBS-1783.
- Use `/Users/pgough/Desktop/projects/regional-observability-service` as a reference. Port only code needed for the current Jira step.
- This is a greenfield project. Do not preserve backwards compatibility by default; make breaking changes when they improve the design, and update affected code, fixtures, tests, and docs together.
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
- Jira MCP and the `jira` CLI are unavailable in this workspace, so Jira was accessed through the authenticated REST API. RHOBS-1798 is a subtask of RHOBS-1783 for error-only access logging. RHOBS-1799 is a separate Story for built-in Prometheus metrics. RHOBS-1801 is a subtask of RHOBS-1783 for host-scoped HTTP/HTTPS support and cert-manager certificate-rotation coverage. RHOBS-1803, RHOBS-1804, and RHOBS-1805 are new RHOBS-1783 subtasks for the local e2e framework, core Kubernetes manifests, and named API/route configuration. They were created in To Do; the authentication-policy API requirement remains unresolved.

## Current state

- The target repo is `/Users/pgough/Desktop/projects/rosa/auth-gateway`. The completed bootstrap branch `rhobs-1783-bootstrap` was fast-forwarded into local `main` at `21f1d89`. No push to remote `main` was made. GitHub currently has no remote `main` branch and lists `rhobs-1783-bootstrap` as its default; local `main` has no existing upstream.
- The bootstrap implementation is complete for this feature branch. RHOBS-1783 remains open until its authentication-policy API requirement is resolved and covered.
- The `config` package loads one strict YAML document, applies defaults, validates it, and generates Envoy config and Kubernetes resources.
- The required `servers` list binds exact DNS hostnames to named APIs on one Envoy port. Each hostname appears once across HTTP and HTTPS. An absent `tls_config` selects HTTP; a non-nil `tls_config` selects HTTPS. There is no wildcard fallback.
- A server exposes only its `apis` bindings. Missing or empty bindings serve 404 for every path. Unknown or repeated bindings are errors. APIs can be reused across servers or remain unbound. Duplicate path/method matches are rejected within an API and across APIs bound to the same server; separate servers can use the same route.
- Each HTTPS server has its own SNI-selected TLS chain, HTTP authority match, and file-based SDS resource. Servers can use separate Kubernetes TLS Secrets or share a certificate. Paths default to `/etc/<secret>/tls.crt` and `tls.key`; file-only TLS without a Secret retains `/etc/auth-gateway-tls` defaults. Identical Secret/path bindings share a mount; conflicting or overlapping mount directories are rejected. Client certificates are not required.
- `config/testdata/server-tls/config.yaml` covers one HTTP and two HTTPS servers, including an empty API binding and distinct Secrets. HTTP and HTTPS share port 8080; the generated Service exposes ports 80 and 443 when those protocols exist. If a proxy terminates caller TLS and forwards plain HTTP, Envoy matches the HTTP `Host`. TLS passthrough or re-encryption must use a configured HTTPS server's SNI hostname.
- The generated HTTP connection manager writes structured JSON access logs to stdout for HTTP status codes of 400 or higher (`config/access_log.go`). RHOBS-1798 tracks this work.
- Each API has one upstream and must define one or more `routes`. Each route must list one or more supported HTTP methods and select exactly one exact path, prefix, or safe RE2 regex match. Missing or empty method lists are configuration errors. An optional path, prefix, or regex rewrite transforms the request path.
- Envoy checks APIs in server binding order, then routes in each API's declaration order. It returns 405 with an `Allow` header only for bound routes with the wrong method, and 404 for unbound or unknown paths.
- Kubernetes output includes the Envoy and collector ConfigMaps, an optional processing ConfigMap when mappings are configured, a ServiceAccount, a Deployment without a checksum annotation, and one Service with ports for configured protocols and metrics. HTTP and HTTPS target the same Envoy listener. SDS and ECDS files are projected into the Envoy container. Envoy runs as UID and GID 101. The Envoy image entrypoint fails when it runs as root.
- The Deployment includes an OpenTelemetry Collector sidecar. It scrapes Envoy's loopback `/stats/prometheus` endpoint on port 9901 every 30 seconds and exposes Prometheus metrics on port 8889. The scrape path is fixed in the generated Collector config. The image is configurable with `kubernetes.otel_collector_image` and defaults to `otel/opentelemetry-collector-contrib:0.135.0`.
- The local Kind fixture defines two HTTP and two HTTPS servers with different API bindings. The Ginkgo suite has HTTP routing/metrics and server TLS groups, each with its own namespace (`auth-gateway-routing-e2e` and `auth-gateway-tls-e2e`). The TLS group checks certificate trust, unknown SNI, mismatched SNI/authority, and API isolation. It renews one of two certificates with `cmctl renew`, then checks that the other certificate and gateway Pod UID stay unchanged. Unknown SNI uses a separate port-forward because the expected TLS reset can close client-go's tunnel. Images remain Envoy 1.39.1, HTTPBin 2.25.0, OpenTelemetry Collector 0.135.0, and cert-manager 1.18.2. Both namespaces are removed at the end; cert-manager remains in the reusable Kind cluster.
- The local e2e suite uses Ginkgo and Gomega. Each use-case group is an `Ordered` container with its own `BeforeAll` setup, fixtures, port forwards, and cleanup. The HTTP group tests routing and metrics; the TLS group also installs cert-manager. Gomega `Eventually` handles readiness, metrics, and certificate rotation polling. The Makefile runs two Ginkgo processes by default; set `GINKGO_PROCS=1` to run serially.
- `e2e/internal/framework` uses client-go with the configured kubeconfig context for server-side manifest apply, namespace lifecycle, readiness checks, Secret and Pod reads, Envoy and Kubernetes diagnostics, and loopback port forwarding. Each Ginkgo process creates its own framework client in `BeforeSuite`. The TLS group installs cert-manager with `Environment.EnsureCertManager` and waits for its Deployments. The framework wraps `cmctl renew` for certificate rotation. The Makefile downloads cmctl v2.6.1 and writes a Ginkgo JSON report under `.state/reports`. `certificates.yaml` remains the cert-manager fixture applied during TLS group setup. Fixture shaping and protocol-specific request helpers remain in `e2e/support_test.go`.
- Config tests load the default, route-list, and TLS fixtures and the root `config.example.yaml`. Tests cover server bindings, route isolation/order, scoped conflicts, TLS defaults, input immutability, and mount conflicts/sharing. TLS ConfigMap and Deployment goldens include multiple SDS files and Secret mounts.
- `docs/tls-secrets.md` describes the Kubernetes Secret projection and Envoy file-based SDS rotation flow, with upstream Envoy and Kubernetes references.
- The PoC's mTLS, SPIFFE, tenant policy, and other gateway features were not ported. JWT support is implemented on RHOBS-1784 below.
- `SERVER-CONFIG-PLAN.md` records the server configuration design and implementation plan. The README and TLS documentation describe the current format and certificate rotation.
- JWT implementation is on the separate RHOBS-1784 feature branch; its current design and checks follow below.

## Checks

For branch closeout, `GOCACHE=/private/tmp/auth-gateway-go-cache make test`, `GOCACHE=/private/tmp/auth-gateway-go-cache go vet ./...`, and `git diff --check` pass. The Kind e2e suite was not rerun for closeout.

For the server configuration work (2026-10-02), `make test`, `go vet ./...`, `go test -tags=e2e -run '^$' ./e2e`, `go vet -tags=e2e ./e2e`, and `make -C e2e test` pass. All 11 Kind specs pass across the default two Ginkgo processes. The TLS test verifies strict SNI/authority and API isolation, then renews one certificate through Secret projection and SDS while the other certificate and gateway Pod UID stay unchanged. Goldens were regenerated with `go test ./config -run Golden -update` and reviewed. Modified Go files are formatted and `git diff --check` passes.

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

## RHOBS-1784 design and initial config implementation (2026-10-02)

- At this initial config stage, `AUTH-PLAN.md` recorded the approved auth design and implementation stages. `config.auth.example.yaml` loaded and validated, while `config.mtls.example.yaml` remained a future mTLS configuration. Envoy auth generation had not started, and `Generate` and `GenerateKubernetes` rejected auth settings so they could not be silently omitted. The completed runtime implementation is described below.
- The initial config step adds public JWT authenticator and claim-mapping types, server authentication and authorization combinations, named policy grants, and per-route request-header mappings. Validation checks HTTPS JWKS URLs, explicit audiences, literal claim paths, mapping values, named references, JWT-only `all_of` limits, header safety, and processing attribute availability for each server binding. Defaults deep-copy the new config fields.
- Each named JWT authenticator now defines one issuer directly. Servers bind authentication and authorization independently using explicit `any_of` or `all_of` lists. Named authorization policies grant access to APIs for named authenticators and mapped attributes; APIs no longer bind policies, and grants no longer need an issuer qualifier.
- Authentication `any_of` selects the first method in declaration order that verifies and maps its credential. Only that identity supplies attributes and grants; authorization denial never retries another method. Envoy's native JWT OR can complete asynchronously, so the gateway must enforce this order independently of completion timing. `all_of` requires every credential, agreement on shared attributes, and preserves provenance when combining other attributes. Requiring two JWT authenticators through `all_of` with the single bearer-token source is a configuration error.
- Authorization `any_of` requires one policy to allow the requested API; `all_of` requires every policy to allow it. Policy order has no effect. Omitted authentication permits public access. Authenticated servers deny API access without a granting policy combination; public servers cannot bind authorization policies.
- Named attributes still use literal JWT claim-path segments and optional value translation. Header output remains optional per route and consumes trusted identity independently of authentication and authorization.
- Any server binding mTLS must require a valid, trusted client certificate at the TLS handshake, including with `any_of`. A JWT can supply the identity after this mandatory handshake; only `all_of` requires the certificate attributes to agree with JWT attributes. The future example shows certificate-only, JWT-first, and combined servers, separate server TLS and client CA Secrets, single URI SAN mapping, and shared `tenant_id` with distinct `jwt_subject` and `certificate_id` attributes.
- Read RHOBS-1782, RHOBS-1783, and RHOBS-1784 through the authenticated Jira REST API for the original proposal. Jira MCP and the Jira CLI were unavailable for the config implementation step, so it followed the checked-in plan. No Jira issues were changed.
- Validated both examples with Ruby/Psych: one YAML document each, no duplicate keys, valid named references and attribute sources, server bindings, image pins, and agreement with the documented permissions. Static checks cover 16 JWT and 16 future mTLS API decisions, method order, and shared-attribute examples. Local links, ASCII content, and whitespace checks pass. These checks do not exercise gateway authentication or TLS. Go and Kind tests were not run for this documentation-only revision.
- For the initial config implementation, `GOCACHE=/private/tmp/auth-gateway-go-cache go test ./config`, `GOCACHE=/private/tmp/auth-gateway-go-cache make test`, `GOCACHE=/private/tmp/auth-gateway-go-cache go vet ./...`, and `git diff --check` pass. Tests load the JWT example, validate configuration references and safety constraints, preserve caller-owned inputs, and verify generation fails closed until runtime support exists. No Kind e2e tests were run because runtime authentication is not implemented.

## Current status

The revised `AUTH-PLAN.md` is implemented on `RHOBS-1784`. JWT verification,
original-claim authorization, ordered attribute mapping, route-specific header
checks, documentation, and JWT lifecycle coverage use native Envoy filters.
Mapping values use a separate ECDS ConfigMap and reload without a rollout. There
is no checksum annotation; static bootstrap changes require an explicit rollout.
mTLS remains future work, and the RHOBS-1783 authentication-policy API question
is still open. The config/runtime and e2e changes are committed; this handover
and the related docs are in the final documentation batch. No Jira issue was
changed, and nothing was pushed.

## RHOBS-1784 native JWT implementation (2026-10-03)

- `jwt_authn` verifies bearer tokens, scopes issuer requirements to each server, and keeps verified payloads in authenticator-specific dynamic metadata. Native RBAC authorizes original claims and APIs before processing, so transformed attributes cannot grant access.
- Native `set_filter_state` extracts configured claims to `auth_gateway.attributes.<name>` and applies ordered mappings after authorization. It compares the `envoy.string` bytes with escaped byte literals. An unmatched lookup returns empty and uses `skip_if_empty` to preserve the existing value, supporting passthrough without Envoy 1.39.1's unsupported CEL `string(bytes)` conversion.
- Route-scoped RBAC checks that required output attributes exist and are safe before native header mutation removes caller-supplied managed headers, adds only the configured headers, and strips the bearer credential. Mapping tables live in `processing.yaml` in a separate processing ConfigMap and load through ECDS. Updating that ConfigMap does not change the bootstrap or Deployment template.
- JWT e2e groups cover plain authorization, direct headers, ordered mappings and passthrough, required-attribute denials, HTTP and HTTPS, issuer isolation, mapping updates through ECDS without replacing the Pod, and JWKS key rotation, outage, cache, and recovery behavior. The tests use signed local JWTs and an in-cluster JWKS endpoint.
- After restoring native ECDS, `GOCACHE=/private/tmp/auth-gateway-go-cache go test ./...`, `go vet ./...`, e2e compile/vet checks, `make update-golden`, the focused JWT Kind suite (10 specs), and the full Kind suite (21 specs) pass. `git diff --check` passes. The e2e mapping update applies only the processing ConfigMap, verifies the changed output, and confirms the Pod UID remains stable.
