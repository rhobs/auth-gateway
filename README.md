# RHOBS Auth Gateway

RHOBS Auth Gateway is a Go configuration library. It loads one YAML document and generates Envoy configuration files or Kubernetes resources. It does not run a controller or gateway process.

The current implementation supports exact-host routing, HTTP and HTTPS listeners, upstream HTTP/1 and HTTP/2, optional JSON Web Token (JWT) and API-key authentication and authorization, attributes from claims, key credentials, and request headers, route-selected request headers, ordered attribute mappings, per-API request counters, Kubernetes packaging, error access logs, Prometheus metrics, and optional Envoy OpenTelemetry traces. Mutual TLS (mTLS) client-certificate authentication is future work. [config.mtls.example.yaml](config.mtls.example.yaml) is an unsupported design sketch and is rejected by the loader.

## Requirements and versioning

Building applications that import this module requires Go 1.26 or later. The floor is deliberate: the code uses Go 1.26's `new(expr)` syntax to create pointers to values.

The module is pre-v1.0 and has no stable Go API compatibility guarantee. Before v1.0, a minor release may contain an incompatible Go API change. After v1.0, incompatible API changes will follow Go module versioning and require a new major version.

The YAML `version` field describes the configuration format and is independent of the Go module version. This code accepts only `version: 1` and rejects unsupported schema versions. A future breaking schema change will increment the YAML version and include migration guidance; the loader will not migrate old configurations automatically.

## Generate and deploy

To deploy on Kubernetes, load a gateway YAML document with `config.Load`, call `config.GenerateKubernetes`, then write `resources.YAML()` to a manifest file. These library calls do not connect to Kubernetes or create referenced credentials. Create the target namespace and any referenced Transport Layer Security (TLS) Secrets, API-key Secret, and certificate authority (CA) ConfigMaps first. TLS Secrets must contain `tls.crt` and `tls.key`; CA ConfigMaps must contain the configured key. Then apply the manifest:

Install the module:

```sh
go get github.com/rhobs/auth-gateway
```

Load and validate YAML from Go:

```go
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/rhobs/auth-gateway/config"
)

func main() {
	gateway, err := config.Load(strings.NewReader(`version: 1
servers:
  - hostname: auth.example.com
    apis: [metrics]
apis:
  - name: metrics
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - methods: [POST]
        path:
          exact: /metrics/api/v1/receive
`))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(gateway.APIs[0].Name)
}
```

Then apply the generated Kubernetes manifest:

```sh
kubectl apply -f auth-gateway.yaml
```

Empty or omitted `kubernetes.image` and `kubernetes.otel_collector_image` values use the Go defaults `config.DefaultEnvoyImage` and `config.DefaultOTelCollectorImage`, listed in the [configuration reference](docs/configuration-reference.md). Set either field to an approved image or private mirror to override its default.

The library also exposes two output paths:

- `config.Generate(cfg)` returns a `config.GeneratedFiles` value with named Envoy files, required absolute paths, and contents. Use it for file-based Envoy deployments. It does not require Kubernetes settings. For API keys, `config.GenerateAPIKeyECDS` returns the separate `api-keys.yaml` file for `config.APIKeyECDSPath`.
- `config.GenerateKubernetes(cfg)` requires the `kubernetes` section and returns typed resources. Call `resources.YAML()` for a multi-document manifest, or `resources.Objects()` when a Kubernetes client needs typed objects.

For a local Envoy demo with unprotected, API-key, JWT, and mixed servers, see [playground/README.md](playground/README.md).

The loader applies defaults, validates references, rejects unknown YAML fields, and requires exactly one document. See the [configuration reference](docs/configuration-reference.md) for every supported field, its default, and its constraints. See [config.example.yaml](config.example.yaml) for routing, [config.auth.example.yaml](config.auth.example.yaml) for JWT, API keys, and request processing, and [config.production.example.yaml](config.production.example.yaml) for capacity settings.

## Routing

A server binds one exact DNS hostname to an ordered list of APIs. Each API has one upstream and an ordered list of routes. Each route requires one or more HTTP methods and one exact path, prefix, or safe regular expression. A rewrite can replace the path, prefix, or regex match.

This is a minimal file-output configuration:

```yaml
version: 1
apis:
  - name: metrics
    upstream:
      address: thanos-receive.observability.svc
      port: 19291
    routes:
      - methods: [POST]
        path:
          exact: /metrics/api/v1/receive
        rewrite:
          path: /api/v1/receive
servers:
  - hostname: write.example.com
    apis: [metrics]
```

The server binding order sets API order. Routes keep their declared order, so put narrower matches first. A request to a known path with an unsupported method gets a local `405` response with an `Allow` header. An unbound hostname or path gets a local `404`. A server without API bindings serves no routes.

All servers share one Envoy listener, port `8080` by default. An entry without `tls_config` serves HTTP. An entry with `tls_config` serves HTTPS. For HTTPS, Envoy selects a certificate by TLS Server Name Indication (SNI), then requires the HTTP `Host` or `:authority` to match the same server.

Kubernetes output exposes Service port `80` when HTTP servers exist and port `443` when HTTPS servers exist. Both target the Envoy listener. For an HTTPS server, set `tls_config.secret` to an existing Kubernetes TLS Secret. Certificate and key paths default to `/etc/<secret>/tls.crt` and `/etc/<secret>/tls.key`. HTTPS termination at Envoy does not request client certificates.

Upstreams use HTTP/1 by default. Set `upstream.http_protocol: http2` only when the backend supports HTTP/2. For TLS upstreams, configure `upstream.tls_config` with the expected DNS name. A configured trusted CA replaces Envoy's system trust bundle. Its YAML form depends on the deployment: use `config_map` for Kubernetes output and `filename` for file-based output without Kubernetes settings. The same choice applies to JWT JWKS trust. JSON Web Key Set (JWKS) endpoints use HTTPS and validate the endpoint identity.

For file-based output, point `trusted_ca.filename` at an absolute CA bundle path that Envoy can read:

```yaml
upstream:
  address: query.backend.example.com
  port: 9091
  tls_config:
    server_name: query.backend.example.com
    trusted_ca:
      filename: /etc/auth-gateway-ca/backend-ca.pem
```

## Authentication and request processing

JWT authentication is optional. Configure named JWT authenticators, bind them to a server, and define authorization policies that grant access to named APIs. Each issuer stays isolated from the others.

API keys use one named `api_key` authenticator per gateway configuration. It declares an optional credential header (default `X-API-Key`). For Kubernetes, `api_key.secret` names the external Secret and is required; the Secret must be in the gateway Deployment's namespace. File-based Envoy deployments can omit `api_key.secret` and write the output of `config.GenerateAPIKeyECDS` to `/etc/auth-gateway/api-keys/api-keys.yaml`.

Declare attributes beside `jwt` or `api_key`. A JWT attribute reads a verified claim with `claim_path` or an incoming header with `header: X-Tenant`. An API-key attribute reads a Secret-bound value with `credential: true` or an incoming header. A header-backed grant still requires its named JWT or API key to authenticate. Grants check original claim, credential, or header values; mappings change only working values used for forwarding and metric labels. Missing or empty headers leave their attributes unset. Header values come from the caller, so include a claim or credential condition in the grant when access must also be tied to that identity.

The [API-key guide](docs/auth/api-key.md) shows the Secret format, client
request, and how attributes affect grants and upstream headers. Keep real keys
and deployed Secret manifests private. Replace the Secret's
`ApiKeyAuth.credentials` list with `[]` to revoke all keys.

On `authentication.any_of` with JWT and API key, a valid JWT wins when both credentials are present. If JWT verification fails or the bearer token is absent, a valid key can authenticate. On mixed `all_of`, both credentials are required. Every attribute declared by both authenticators must be a nonempty scalar string with exactly the same raw value. At most one JWT authenticator and one API-key authenticator may be selected by `all_of`.

Choose request processing per route:

- With no route header mappings, authorization can run without attribute processing.
- Use `routes[].processing.request_headers` to set selected upstream headers from declared attributes.
- Add top-level `processing` attribute-mapper entries to translate attribute values before the configured headers are written. Processors run in declaration order. Each mapping table performs one exact lookup; an unmatched value passes through.

The gateway replaces caller-supplied values for managed output headers and removes bearer tokens and API keys before forwarding. Other source headers remain on the upstream request. A missing claim or source header does not invalidate an otherwise valid credential. A missing attribute needed for authorization denies the request. A missing or unsafe attribute required by a route header returns `403` before the request reaches the backend.

See the [auth method guides](docs/auth/README.md) for JWT and API-key
setup, [config.auth.example.yaml](config.auth.example.yaml) for complete
examples, and [docs/envoy.md](docs/envoy.md) for the native Envoy filter
behavior.

## Timeouts and capacity

Write duration values as YAML strings with units, such as `5s`, `250ms`, or `1m`. Current duration settings must be at least `1ms`. Omitted or `null` optional settings use their defaults. API and route timeout overrides inherit independently: route values override API values, and omitted idle and stream-duration values inherit from the listener. The default response timeout is `30s`.

An explicit zero is treated as a supplied value and is rejected where a positive value is required. A circuit-breaker `max_retries: 0` is valid and does not create a retry policy. Omitted Kubernetes resource maps use defaults; supply an empty map such as `limits: {}` to disable defaults for that map.

Overload protection is disabled unless the top-level `overload` section is present. Set both `max_heap_bytes` and `max_downstream_connections`; the heap budget must be less than Envoy's memory limit. The default heap-shrink and request-reject thresholds are `0.90` and `0.95`.

Kubernetes metrics collection is enabled by default. Set `observability.metrics` to change the scrape interval and timeout, or set `observability.metrics.enabled: false` to omit metrics scraping and the metrics Service port. That flag does not change which per-API counters Envoy generates. Set `observability.tracing.enabled: true` to enable Envoy spans; the collector sidecar exports them to `observability.tracing.endpoint`. The collector remains when either metrics or tracing is enabled. Collector resources remain under `kubernetes.metrics.resources`. The default Envoy and collector image versions are documented in [configuration-reference.md](docs/configuration-reference.md). Omit `kubernetes.envoy_concurrency` to let Envoy choose its worker count; a CPU limit does not set it.

## Applying updates

| Change | Required action and effect |
| --- | --- |
| Values in existing attribute mapping tables | Regenerate and apply the processing ConfigMap. Envoy's Extension Config Discovery Service (ECDS) reloads the mappings and request metric label values without a Pod restart. |
| API-key values or their attribute values | Regenerate and apply the same namespace Secret. ECDS reloads the complete key set without a Pod restart. Envoy keeps its last accepted set if an update is invalid and exports an update-failure counter; see [Envoy operations](docs/envoy.md#kubernetes-files-and-reloads). Set `credentials: []` in the Secret's `ApiKeyAuth` resource for revocation. |
| Downstream certificate or key in a mounted TLS Secret | Update the Secret. Envoy's Secret Discovery Service (SDS) reloads it for new TLS connections. |
| `observability.metrics.scrape_interval` or `observability.metrics.scrape_timeout` | Regenerate and apply resources, then restart the gateway so the collector loads its updated ConfigMap. |
| `observability.tracing.endpoint` or `observability.tracing.insecure` | Regenerate and apply resources, then restart the gateway so the collector loads its updated ConfigMap. |
| `observability.tracing.enabled`, `service_name`, or `sampling_percentage` | Regenerate and apply resources, then roll out the gateway to load the changed Envoy bootstrap. |
| Routes, authenticator attribute sources, the request metric name or label bindings, other static configuration, or deployment settings | Regenerate and apply the resources. Roll out the gateway when the static Envoy configuration changes. |
| Upstream or JWKS CA bundle | Update the referenced bundle and explicitly roll out the gateway. |

The Deployment has no generated checksum annotation. A changed ConfigMap alone does not restart Pods for static configuration.

## Logs and metrics

Envoy writes structured JSON access logs to stdout for responses with status `400` or higher. Entries include the route, method, status, duration, response details, and upstream information.

Kubernetes output includes an OpenTelemetry Collector sidecar when either `observability.metrics.enabled` or `observability.tracing.enabled` is true. When metrics are enabled, it scrapes Envoy's admin endpoint at `127.0.0.1:9901/stats/prometheus` and serves Prometheus metrics at `/metrics` on port `8889` of the gateway Service. When tracing is enabled, its OTLP/gRPC receiver listens on `127.0.0.1:4317` and is not exposed through the Service. The Envoy admin endpoint remains bound to loopback and is not exposed through the Service.

Set `apis[].metrics` to count responses for an API. `metrics: {}` records `api` and the exact downstream `http_status_code`. Use `metrics.labels` to bind more Prometheus labels to processed attributes, including header-backed attributes, for example `tenant: requested_tenant`. Enabled APIs share the union of configured label names; missing, unavailable, or unsafe values use `__unattributed__`. Envoy adds the `envoy_http_lua_` prefix to these counters, and the collector removes it before exposing the series. The default exported metric is `auth_gateway_http_requests_total`; set `observability.metrics.custom_metric_name` to change it. The counter includes authentication and RBAC denials as well as upstream responses. Gateway 404 and 405 fallback routes have no custom counter.

Label values must be 1 to 128 printable ASCII bytes and cannot contain `|`. Label names use Prometheus ASCII syntax and cannot be `api`, `http_status_code`, `envoy_http_conn_manager_prefix`, or start with `__`. Each distinct label combination stays in Envoy memory until the process restarts, so choose labels with bounded values.

Set `observability.tracing.enabled: true` to enable Envoy's native OpenTelemetry HTTP tracer. Envoy sends sampled OTLP/gRPC spans to the local collector at `127.0.0.1:4317`, and the collector exports them to the required `observability.tracing.endpoint` (`host:port`). TLS is enabled by default; set `insecure: true` only for a trusted plaintext endpoint. The service name defaults to `node.cluster`, and `sampling_percentage` defaults to `100` and accepts values from `0` to `100`. Tracing starts the collector even when metrics are disabled; the OTLP receiver remains local to the Pod and is not exposed by the Service. For file-based Envoy output, configure a collector yourself to receive on the local OTLP port and export to the same endpoint.

For generator details, filter order, trust, and reload mechanics, see [docs/envoy.md](docs/envoy.md). For local checks, test ownership, and golden updates, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
