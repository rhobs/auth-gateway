# Envoy configuration and runtime behavior

This document explains how the Go configuration library builds Envoy resources. For configuration and deployment steps, start with the [README](../README.md).

## Generation flow and outputs

```text
one strict YAML document
  -> config.Load: defaults and validation
  -> resolve API and route settings on a private copy
  -> config.Generate: Envoy files
     or config.GenerateKubernetes: Kubernetes resources
```

`Load` rejects unknown fields and extra YAML documents. It returns a defaulted configuration without materializing inherited API and route timeout overrides. Validation and generation resolve effective timeouts on a copy, so caller-owned maps, slices, and pointers remain unchanged.

`Generate` returns a `config.GeneratedFiles` value with named Envoy bootstrap, optional processing configuration, and one file-based Secret Discovery Service (SDS) resource for each HTTPS server. Each generated file includes its required absolute path and contents. It does not require Kubernetes settings.

`GenerateKubernetes` requires the `kubernetes` section. It returns the main `<name>-config` ConfigMap, an optional `<name>-processing` ConfigMap, an optional collector ConfigMap when metrics or traces are enabled, a ServiceAccount, a Deployment, and a Service. The main ConfigMap contains the Envoy bootstrap and file-based Transport Layer Security (TLS) SDS resources. Certificate authority (CA) ConfigMaps, TLS Secrets, and the API-key Secret remain external references. `config.APIKeySecret` builds the latter. `YAML` serializes the resources as a multi-document stream. `Objects` returns typed Kubernetes objects in apply order.

### File-based output layout

`GeneratedFiles.All()` returns every file created by `Generate`. Each file's
`Path` is the absolute location Envoy uses, and `Contents` contains the resource
to write there.

| Resource | Required path | Source |
| --- | --- | --- |
| Envoy bootstrap | `/etc/auth-gateway/envoy.yaml` | `config.GeneratedFiles.EnvoyBootstrap` |
| Attribute processing ECDS resource, when mappings are configured | `/etc/auth-gateway/processing/processing.yaml` | `config.GeneratedFiles.ProcessingConfig` |
| One TLS SDS resource per HTTPS server | `/etc/auth-gateway/server-certificate-N.yaml`, where `N` is its zero-based position in `servers` | `config.GeneratedFiles.ServerCertificateResources` |
| API-key ECDS resource, when API keys are used | `/etc/auth-gateway/api-keys/api-keys.yaml` | `config.GenerateAPIKeyECDS`; path constant `config.APIKeyECDSPath` |
| CA ConfigMap entry | `/etc/auth-gateway-ca/<hashed-id>/ca.crt` | `config.CAConfigMap.FilePath()` |

`Generate` creates the bootstrap, processing, and TLS SDS files. It does not
copy downstream certificate or private-key material; those files must exist at
the paths configured for the HTTPS server. API-key ECDS content is generated
separately. `GenerateKubernetes` mounts API-key Secrets and CA ConfigMaps at the
same paths automatically; file-based Envoy deployments must provide those
external resources at the paths above. A `TrustedCA.Filename` is already the
required path for file-based CA configuration.

## Listener, hosts, and routes

One Envoy listener serves all configured servers. Its address defaults to `0.0.0.0:8080`. Servers without TLS share an HTTP filter chain. HTTPS servers use the TLS inspector and select a filter chain by Server Name Indication (SNI). The HTTP virtual host then matches the exact `Host` or `:authority`; a successful TLS handshake alone does not select the API.

Each server exposes only the APIs in its `apis` list. The list order controls API route order for that host. Routes within an API preserve their declaration order. Matches use an exact path, prefix, or safe regular expression. Rewrites replace the matched path, prefix, or regex capture. A path match with no allowed method returns a local `405` and the combined `Allow` header. Unmatched hosts and paths return local `404` responses.

## Conditional HTTP filter chain

Public requests use request-control header removal and the router. Metered routes add the existing Lua response counter. Protected requests select these native Envoy filters as needed:

```text
auth_gateway.request_controls
  -> [envoy.filters.http.lua]                  (response counter)
  -> [envoy.filters.http.jwt_authn]
  -> [envoy.filters.http.api_key_auth]         (Secret-backed ECDS)
  -> [envoy.filters.http.header_to_metadata]  (key identity and source headers)
  -> [auth_gateway.authentication]             (mixed credential RBAC)
  -> [auth_gateway.attributes.server-N]        (working attributes)
  -> [envoy.filters.http.set_filter_state]     (mapping ECDS)
  -> envoy.filters.http.rbac                   (raw attribute grants)
  -> [auth_gateway.required_headers]           (route-specific checks)
  -> [auth_gateway.credentials]                (credential removal)
  -> [envoy.filters.http.header_mutation]      (managed upstream headers)
  -> envoy.filters.http.router
```

The request-control filter removes fixed Envoy retry, timeout, and alternate-stat headers on both public and protected chains. These controls cannot be passed through as identity headers.

The JWT filter validates signature, issuer, expiration, and not-before values. If an authenticator sets `audiences`, the filter also requires the token's `aud` claim to match one of them. It reads the bearer token from `Authorization` and stores each provider's verified claims in separate Envoy dynamic metadata. The API-key filter reads the configured header, validates it against one ECDS credential set, and forwards a verified identity through an internal header. The identity has alphabetically ordered credential `attribute=value` fields. Generated `header_to_metadata` rules copy the identity, extract each credential attribute with a regex, then remove the internal header. The same filter captures each distinct declared source header once in separate dynamic metadata without removing it. Request controls remove caller-supplied identity markers before either credential filter runs. No new Lua handles authentication or attributes.

On mixed `authentication.any_of`, the JWT filter permits a missing or failed token so a key can be tried. A verified JWT writes a marker that makes the API-key matcher skip key validation, including when a key is also present. Authorization then uses the JWT's named metadata. A valid but unprivileged JWT does not fall back to a key. On mixed `all_of`, JWT verification is strict and the key filter also runs. The authentication RBAC rule requires both credentials. For every attribute declared by both authenticators, it also requires nonempty scalar strings with exact equality in their original claim, credential, or header sources. Missing or invalid credentials return `401`; a valid identity without a matching grant, or with unequal shared attributes, returns `403`.

Attribute initialization runs when request headers or metric labels need working attributes. With API keys, host-scoped inline `set_filter_state` filters initialize them from the selected JWT or key, including its declared source headers. The separate ECDS `set_filter_state` filter then applies mappings. JWT-only configurations initialize attributes in the same stage as their mappings, either inline or through ECDS. Header initialization checks the named authenticator's verified identity before copying a value, so an unselected header source cannot replace the selected value on mixed `any_of`. Authorization RBAC reads original claim, credential, or source-header metadata. Required-header checks run after authorization and before header mutation. The credential cleanup filter removes `Authorization`, the configured key header, and internal markers, including on public chains in a gateway that uses keys. Header mutation removes caller values for every managed output name and sets the selected route's outputs. The router forwards only after these filters allow the request.

## Attribute sources and working values

A JWT attribute's `claim_path` is a list of literal object keys. For example, `[organization, id]` reads two nested keys, while `[customer.id]` reads one top-level key containing a dot. To authorize `{"x":{"my_list":["y","z"]}}`, set `claim_path: [x, my_list]` and allow values with `attributes.my_list: [y, z]`. Any string member that matches an allowed value is sufficient; scalar claims still use exact matching. The path may end at a list-valued claim, but it cannot traverse into a list. Different attributes in one grant must all match.

Declare attributes beside `jwt` or `api_key`. JWT attributes use `claim_path` or `header`; API-key attributes use `credential: true` or `header`. Working attributes used for processing require a nonempty scalar string. Missing, null, empty, non-string, or list-valued claims leave the corresponding working attribute unset; they do not invalidate an otherwise valid JWT. A missing or empty source header also leaves its attribute unset. Each API-key credential stores only its declared credential-backed string attributes in the Secret. Key grants match exact original values, and missing attributes deny any grant that requires them.

Authorization grants are tied to a named authenticator and use its original claim, credential, or source-header values. A header-only JWT grant also checks the verified issuer; a header-only key grant also checks the verified key identity. A caller can choose a source-header value, but cannot use it to bypass authentication. The optional top-level `processing` list changes working attributes after authentication and before RBAC. Each processor performs one exact lookup per configured attribute. Entries in one table do not chain. Later processors see earlier results and may replace them. Unmatched values pass through. Mappings do not change raw authorization decisions. Header-backed grants do depend on the original caller-supplied header.

Envoy `v1.39.1` exposes `envoy.string` filter-state values as bytes in Common Expression Language (CEL). The generator compares mapping inputs with byte literals and uses `skip_if_empty` so unmatched values pass through and missing values do not become placeholder strings. It emits one update per attribute per processor to preserve processor order.

A route that selects output headers also selects required working attributes. If an attribute is missing or unsuitable for an HTTP header after processing, the required-header RBAC filter returns `403` before upstream delivery. A caller-supplied output header cannot fill the missing value. If a source header has a managed output name, the source is captured before mutation; that name is replaced on routes with an output and removed on other routes. Other source headers pass through.

## JWT and upstream trust

Each JWT authenticator gets its own JSON Web Key Set (JWKS) cluster and cache, even when providers share a URI. JWKS fetching is on demand and cache state is per worker. A usable cached key may survive a short issuer outage. A cold cache or expired key fails closed when the issuer is unavailable. Cache duration does not guarantee immediate key revocation; rotate keys with an overlap period.

JWKS and TLS upstream connections verify certificate chains and endpoint identity. The default trust bundle is `/etc/ssl/certs/ca-certificates.crt`. A configured CA replaces system trust. DNS identities use SNI and hostname validation. IP upstreams use IP Subject Alternative Name validation. Kubernetes CA ConfigMaps are mounted under `/etc/auth-gateway-ca`; a changed CA bundle requires a rollout.

Upstreams use HTTP/1 unless `http_protocol: http2` is set. HTTP/2 connection options are emitted only for explicit HTTP/2 configuration. Circuit-breaker values control cluster limits; a nonzero retry breaker does not add a retry policy.

## Kubernetes files and reloads

The Envoy bootstrap and SDS resource files are projected from the main ConfigMap. TLS Secrets are mounted as read-only directories without `subPath`, so Kubernetes can refresh their projected files. Identical Secret and path bindings share a volume mount; different server chains keep separate SDS resources. File-only generation returns those SDS files but does not create or mount the certificate material.

When mappings exist, the generator puts `processing.yaml` in the separate processing ConfigMap and mounts it at `/etc/auth-gateway/processing`. This file is an ECDS resource for `envoy.filters.http.set_filter_state`. With keys, it contains only mapping updates; host-scoped initializers in the bootstrap extract claims, credential attributes, or source headers first. JWT-only configurations keep attribute extraction in the ECDS resource. Envoy watches the mounted directory. Updating mapping values changes only that ConfigMap. The bootstrap, Deployment template, and Pod identity remain unchanged.

All keys used by this gateway's servers live in one same-namespace Secret with an `api-keys.yaml` entry. The Deployment mounts that Secret as a read-only directory at `/etc/auth-gateway/api-keys`, without `subPath`, and Envoy watches it through ECDS. Each credential binds an opaque key to the named authenticator and its original attributes. Replacing the Secret entry replaces the complete accepted key set across HTTP and HTTPS chains without changing the Pod. Envoy keeps its last accepted set if a projected update is invalid. Apply a valid resource with `credentials: []` to revoke every key; deleting or corrupting the Secret is not a revocation method. Kubernetes volumes cannot read Secrets across namespaces, so each gateway Deployment uses a Secret in its own namespace. The same Secret name may have independent contents in another namespace.

### API-key Secret format

The application that provisions keys can load a small credential document with
`config.LoadAPIKeyCredentials`, then use `config.APIKeySecret` to produce the
Kubernetes Secret. For a key authenticator declaring `tenant_id` and
`writer_id` with `credential: true`, the input is:

```yaml
credentials:
  - key: example-partner-key
    attributes:
      tenant_id: client-123
      writer_id: writer-17
```

Only credential-backed attributes belong in this document. Header-backed
attributes come from each request. `config.APIKeySecret` writes the generated
ECDS resource into `Secret.data["api-keys.yaml"]`. The equivalent manually
written Secret below uses `stringData` for readability. The `client` field
lists credential attributes alphabetically, with empty values for missing
bindings:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-gateway-api-keys
  namespace: observability
type: Opaque
stringData:
  api-keys.yaml: |
    resources:
      - '@type': type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig
        name: envoy.filters.http.api_key_auth
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.common.matching.v3.ExtensionWithMatcher
          extension_config:
            name: envoy.filters.http.api_key_auth
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.api_key_auth.v3.ApiKeyAuth
              credentials:
                - client: tenant_id=client-123;writer_id=writer-17
                  key: example-partner-key
              forwarding:
                header: x-auth-gateway-api-key-client
                hide_credentials: true
              key_sources:
                - cookie: ""
                  header: x-partner-key
                  query: ""
```

The example `key_sources.header` matches `api_key.header: X-Partner-Key`.
Credential values cannot contain semicolons. Use a different key for real
clients. An input document with `credentials: []`, or an Envoy Secret
resource with `ApiKeyAuth.credentials: []`, revokes all keys.

### Mapping and rollout behavior

The static bootstrap embeds the shared request metric name, Lua's label names, and each API's label-to-attribute bindings in route metadata. Attribute mapping tables stay in the ECDS-loaded `set_filter_state` filter. Lua reads its processed values. For example, `tenant: requested_tenant` with a `client-123: team-a` mapping emits `tenant="team-a"` for `X-Tenant: client-123`, while RBAC checks the original `client-123`. Changing the metric name or a binding requires a rollout; changing a mapping value updates only the processing ConfigMap and changes subsequent metric labels without a Pod restart.

SDS reloads updated downstream certificates and keys for new TLS connections. ECDS reloads mapping tables and the API-key credential set. Routes, authenticator definitions (including attribute sources and credential headers), authorization policies, other bootstrap data, deployment settings, and upstream/JWKS CA bundles require the documented regeneration and rollout steps. The generator does not add a checksum annotation.

## Timeouts, overload, logs, metrics, and traces

Listener defaults include a `5s` request-header timeout, `30s` request timeout, `60s` connection and stream idle timeouts, and `30s` maximum stream duration. API and route values override independently. Route values take precedence over API values. Response timeout defaults to `30s`; omitted idle and maximum stream duration values inherit from the listener. Current duration settings must be at least `1ms`.

The request-control filter strips client-supplied Envoy timeout and retry headers. The generator does not infer worker count from CPU limits. When `kubernetes.envoy_concurrency` is omitted, Envoy selects its worker count.

Overload protection is opt-in. Its fixed heap monitor and global downstream-connection monitor use the configured budgets. The default heap-shrink threshold is `0.90`; the default request-reject threshold is `0.95`. Kubernetes generation requires the heap budget to be below the Envoy memory limit.

The Envoy access logger writes structured JSON to stdout for HTTP responses with status `400` or higher. When `observability.metrics.enabled` is true (the default), a Kubernetes OpenTelemetry Collector sidecar scrapes `127.0.0.1:9901/stats/prometheus` every `30s` by default, with a `10s` timeout, and exposes metrics at `/metrics` on port `8889`. Set the scrape timing under `observability.metrics`; collector resources remain under `kubernetes.metrics.resources`. Setting `observability.metrics.enabled: false` omits metrics scraping and the metrics Service port, while API counter generation under `apis[].metrics` remains independent. The Envoy admin endpoint stays on loopback and is not published by the Service.

Set `observability.tracing.enabled: true` to enable Envoy's native OpenTelemetry HTTP tracer. Envoy sends OTLP/gRPC spans to the local collector at `127.0.0.1:4317`; the collector exports them to the required `observability.tracing.endpoint` (`host:port`). TLS is enabled by default; set `insecure: true` only for a trusted plaintext endpoint. The service name defaults to `node.cluster`, and `sampling_percentage` defaults to `100` and accepts values from `0` to `100`. The collector sidecar is generated when either metrics or tracing is enabled, and its OTLP receiver is not exposed through the Service. With file-based Envoy generation, configure a collector yourself to receive on the local OTLP port and export to the configured endpoint. Changing the endpoint or its TLS mode requires the collector to load its updated ConfigMap; the Deployment has no checksum annotation.

For each API with `metrics` configured, a stats-only Lua filter counts responses by `api`, exact downstream `http_status_code`, and the union of configured label names. `metrics: {}` enables the counter without attribute bindings. Lua runs before authentication so it sees JWT, API-key, and RBAC local replies; it reads processed filter state in its response callback. Named API routes carry the metric metadata. Gateway 404 and 405 fallback routes do not, so they are excluded. A missing, unavailable, empty, non-ASCII, control-character, over-128-byte, or `|`-containing attribute becomes `__unattributed__`.

Envoy exposes the series as `envoy_http_lua_<name>` after extracting stat tags. The OpenTelemetry Collector strips that prefix before exposing the metric to Prometheus, so `observability.metrics.custom_metric_name` is the exported name. It defaults to `auth_gateway_http_requests_total` and must use ASCII letters, numbers, and underscores, start with a letter or underscore, and not start with `__`. Setting the name alone does not enable the counter; APIs still need `metrics`. The counter covers responses that reach Lua. Envoy retains each distinct label combination in memory until restart; use bounded label values.
