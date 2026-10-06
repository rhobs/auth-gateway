# RHOBS Auth Gateway

RHOBS Auth Gateway is a Go configuration library. It loads one YAML document and generates Envoy configuration files or Kubernetes resources. It does not run a controller or gateway process.

The current implementation supports exact-host routing, HTTP and HTTPS listeners, upstream HTTP/1 and HTTP/2, optional JSON Web Token (JWT) and API-key authentication and authorization, route-selected request headers, ordered attribute mappings, per-API request counters, Kubernetes packaging, error access logs, and Prometheus metrics. Mutual TLS (mTLS) client-certificate authentication is future work. [config.mtls.example.yaml](config.mtls.example.yaml) is an unsupported design sketch and is rejected by the loader.

## Generate and deploy

To deploy on Kubernetes, load a gateway YAML document with `config.Load`, call `config.GenerateKubernetes`, then write `resources.YAML()` to a manifest file. These library calls do not connect to Kubernetes or create referenced credentials. Create the target namespace and any referenced Transport Layer Security (TLS) Secrets, API-key Secret, and certificate authority (CA) ConfigMaps first. TLS Secrets must contain `tls.crt` and `tls.key`; CA ConfigMaps must contain the configured key. Then apply the manifest:

```sh
kubectl apply -f auth-gateway.yaml
```

The examples use Envoy `v1.39.1`. Use an Envoy image compatible with the generated configuration.

The library also exposes two output paths:

- `config.Generate(cfg)` returns a map of Envoy filenames to file contents. Use it for file-based Envoy deployments. It does not require Kubernetes settings. For API keys, `config.GenerateAPIKeyECDS` returns the separate `api-keys.yaml` file.
- `config.GenerateKubernetes(cfg)` requires the `kubernetes` section and returns typed resources. Call `resources.YAML()` for a multi-document manifest, or `resources.Objects()` when a Kubernetes client needs typed objects.

For a local Envoy demo with unprotected, API-key, JWT, and mixed servers, see [playground/README.md](playground/README.md).

The loader applies defaults, validates references, rejects unknown YAML fields, and requires exactly one document. See [config.example.yaml](config.example.yaml) for routing, [config.auth.example.yaml](config.auth.example.yaml) for JWT, API keys, and request processing, and [config.production.example.yaml](config.production.example.yaml) for capacity settings.

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

Upstreams use HTTP/1 by default. Set `upstream.http_protocol: http2` only when the backend supports HTTP/2. For TLS upstreams, configure `upstream.tls_config` with the expected DNS name and, when needed, a trusted CA. JSON Web Key Set (JWKS) endpoints use HTTPS and validate the endpoint identity.

## Authentication and request processing

JWT authentication is optional. Configure named JWT authenticators, bind them to a server, and define authorization policies that grant access to named APIs using claims from a specific authenticator. Authorization reads the original verified claims, so attribute mappings cannot change a grant. Each issuer stays isolated from the others.

API keys use one named `api_key` authenticator per gateway configuration. It declares an optional request header (default `X-API-Key`) and the attribute names that credentials may provide. For Kubernetes, `api_key.secret` names the external Secret and is required; the Secret must be in the gateway Deployment's namespace. File-based Envoy deployments can omit `api_key.secret` and write the output of `config.GenerateAPIKeyECDS` to `/etc/auth-gateway/api-keys/api-keys.yaml`. Authorization grants match the key's original attribute values, using the same policy layout as JWT grants.

The [API-key guide](docs/auth/api-key.md) shows the Secret format, client
request, and how attributes affect grants and upstream headers. Keep real keys
and deployed Secret manifests private. Replace the Secret's
`ApiKeyAuth.credentials` list with `[]` to revoke all keys.

On `authentication.any_of` with JWT and API key, a valid JWT wins when both credentials are present. If JWT verification fails or the bearer token is absent, a valid key can authenticate. On mixed `all_of`, both credentials are required. Every attribute declared by both authenticators must be a nonempty scalar string with exactly the same raw value. At most one JWT authenticator and one API-key authenticator may be selected by `all_of`.

Choose request processing per route:

- With no route header mappings, authorization can run without attribute processing.
- Use `routes[].processing.request_headers` to set selected upstream headers from verified JWT or API-key attributes.
- Add top-level `processing` attribute-mapper entries to translate attribute values before the configured headers are written. Processors run in declaration order. Each mapping table performs one exact lookup; an unmatched value passes through.

The gateway replaces caller-supplied values for managed headers and removes bearer tokens and API keys before forwarding. A missing claim does not invalidate an otherwise valid token. A missing attribute needed for authorization denies the request. A missing or unsafe attribute required by a route header returns `403` before the request reaches the backend.

See the [auth method guides](docs/auth/README.md) for JWT and API-key
setup, [config.auth.example.yaml](config.auth.example.yaml) for complete
examples, and [docs/envoy.md](docs/envoy.md) for the native Envoy filter
behavior.

## Timeouts and capacity

Write duration values as YAML strings with units, such as `5s`, `250ms`, or `1m`. Current duration settings must be at least `1ms`. Omitted or `null` optional settings use their defaults. API and route timeout overrides inherit independently: route values override API values, and omitted idle and stream-duration values inherit from the listener. The default response timeout is `30s`.

An explicit zero is treated as a supplied value and is rejected where a positive value is required. A circuit-breaker `max_retries: 0` is valid and does not create a retry policy. Omitted Kubernetes resource maps use defaults; supply an empty map such as `limits: {}` to disable defaults for that map.

Overload protection is disabled unless the top-level `overload` section is present. Set both `max_heap_bytes` and `max_downstream_connections`; the heap budget must be less than Envoy's memory limit. The default heap-shrink and request-reject thresholds are `0.90` and `0.95`.

Kubernetes metrics scrape Envoy every `30s` by default with a `10s` timeout. Set `kubernetes.metrics` to change scrape timing and collector resources. The default collector image is `otel/opentelemetry-collector-contrib:0.135.0`. Omit `kubernetes.envoy_concurrency` to let Envoy choose its worker count; a CPU limit does not set it.

## Applying updates

| Change | Required action and effect |
| --- | --- |
| Values in existing attribute mapping tables | Regenerate and apply the processing ConfigMap. Envoy's Extension Config Discovery Service (ECDS) reloads the mappings and request metric label values without a Pod restart. |
| API-key values or their attribute values | Regenerate and apply the same namespace Secret. ECDS reloads the complete key set without a Pod restart. An invalid update leaves the last accepted set active; set `credentials: []` in the Secret's `ApiKeyAuth` resource for revocation. |
| Downstream certificate or key in a mounted TLS Secret | Update the Secret. Envoy's Secret Discovery Service (SDS) reloads it for new TLS connections. |
| Routes, providers, the request metric name or label bindings, other static configuration, or deployment settings | Regenerate and apply the resources. Roll out the gateway when the static Envoy configuration changes. |
| Upstream or JWKS CA bundle | Update the referenced bundle and explicitly roll out the gateway. |

The Deployment has no generated checksum annotation. A changed ConfigMap alone does not restart Pods for static configuration.

## Logs and metrics

Envoy writes structured JSON access logs to stdout for responses with status `400` or higher. Entries include the route, method, status, duration, response details, and upstream information.

Kubernetes output includes an OpenTelemetry Collector sidecar. It scrapes Envoy's admin endpoint at `127.0.0.1:9901/stats/prometheus` and serves Prometheus metrics at `/metrics` on port `8889` of the gateway Service. The admin endpoint remains bound to loopback and is not exposed through the Service.

Set `apis[].metrics` to count responses for an API. `metrics: {}` records `api` and the exact downstream `http_status_code`. Use `metrics.labels` to bind more Prometheus labels to processed JWT or API-key attributes, for example `tenant: tenant_id`. Enabled APIs share the union of configured label names; missing, unavailable, or unsafe values use `__unattributed__`. The default metric is `envoy_http_lua_auth_gateway_http_requests_total`. Set top-level `request_metrics.name` to change the shared name after Envoy's `envoy_http_lua_` prefix. The counter includes responses handled by the existing stats-only Lua filter, such as authentication and RBAC denials and upstream responses. Gateway 404 and 405 fallback routes have no custom counter.

Label values must be 1 to 128 printable ASCII bytes and cannot contain `|`. Label names use Prometheus ASCII syntax and cannot be `api`, `http_status_code`, `envoy_http_conn_manager_prefix`, or start with `__`. Each distinct label combination stays in Envoy memory until the process restarts, so choose labels with bounded values.

For generator details, filter order, trust, and reload mechanics, see [docs/envoy.md](docs/envoy.md). For local checks, test ownership, and golden updates, see [CONTRIBUTING.md](CONTRIBUTING.md).
