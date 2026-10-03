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

`Generate` returns `envoy.yaml`, plus `processing.yaml` when attribute mappings are configured and one file-based Secret Discovery Service (SDS) resource for each HTTPS server. It does not require Kubernetes settings.

`GenerateKubernetes` requires the `kubernetes` section. It returns the main `<name>-config` ConfigMap, an optional `<name>-processing` ConfigMap, a metrics ConfigMap, a ServiceAccount, a Deployment, and a Service. The main ConfigMap contains the Envoy bootstrap and file-based Transport Layer Security (TLS) SDS resources. Certificate authority (CA) ConfigMaps and TLS Secrets remain external references. `YAML` serializes the resources as a multi-document stream. `Objects` returns typed Kubernetes objects in apply order.

## Listener, hosts, and routes

One Envoy listener serves all configured servers. Its address defaults to `0.0.0.0:8080`. Servers without TLS share an HTTP filter chain. HTTPS servers use the TLS inspector and select a filter chain by Server Name Indication (SNI). The HTTP virtual host then matches the exact `Host` or `:authority`; a successful TLS handshake alone does not select the API.

Each server exposes only the APIs in its `apis` list. The list order controls API route order for that host. Routes within an API preserve their declaration order. Matches use an exact path, prefix, or safe regular expression. Rewrites replace the matched path, prefix, or regex capture. A path match with no allowed method returns a local `405` and the combined `Allow` header. Unmatched hosts and paths return local `404` responses.

## Conditional HTTP filter chain

Public requests use request-control header removal and the router. Protected requests add only the filters required by their configuration. The JSON Web Token (JWT) filter validates credentials, and the role-based access control (RBAC) filter enforces authorization:

```text
auth_gateway.request_controls
  -> envoy.filters.http.jwt_authn
  -> envoy.filters.http.rbac                 (original-claim authorization)
  -> [envoy.filters.http.set_filter_state]   (working attributes and mappings)
  -> [auth_gateway.required_headers]         (route-specific checks)
  -> [envoy.filters.http.header_mutation]    (managed upstream headers)
  -> envoy.filters.http.router
```

The request-control filter removes fixed Envoy retry, timeout, and alternate-stat headers on both public and protected chains. These controls cannot be passed through as identity headers.

The JWT filter validates signature, issuer, audience, expiration, and not-before values. It reads the bearer token from `Authorization` and stores each provider's verified claims in separate Envoy dynamic metadata. RBAC then authorizes the selected API against the named provider's original metadata. It does not read transformed attributes or caller-supplied headers.

Attribute initialization runs only when a route or policy needs JWT attributes. Mapping updates run in the same `set_filter_state` stage after authorization. Required-header checks run after processing and before header mutation. Header mutation removes caller values for managed names, then sets the selected route's outputs. The router forwards only after these filters allow the request.

## Original claims and working attributes

A JWT attribute's `claim_path` is a list of literal object keys. For example, `[organization, id]` reads two nested keys, while `[customer.id]` reads one top-level key containing a dot. Missing, null, empty, or non-string claim values leave the corresponding working attribute unset; they do not invalidate an otherwise valid JWT.

Authorization grants are tied to a named authenticator and use its original claim values. The optional top-level `processing` list changes working attributes only after authorization. Each processor performs one exact lookup per configured attribute. Entries in one table do not chain. Later processors see earlier results and may replace them. Unmatched values pass through.

Envoy `v1.39.1` exposes `envoy.string` filter-state values as bytes in Common Expression Language (CEL). The generator compares mapping inputs with byte literals and uses `skip_if_empty` so unmatched values pass through and missing values do not become placeholder strings. It emits one update per attribute per processor to preserve processor order.

A route that selects request headers also selects required working attributes. If an attribute is missing or unsuitable for an HTTP header after processing, the required-header RBAC filter returns `403` before upstream delivery. A caller-supplied header cannot fill the missing value.

## JWT and upstream trust

Each JWT authenticator gets its own JSON Web Key Set (JWKS) cluster and cache, even when providers share a URI. JWKS fetching is on demand and cache state is per worker. A usable cached key may survive a short issuer outage. A cold cache or expired key fails closed when the issuer is unavailable. Cache duration does not guarantee immediate key revocation; rotate keys with an overlap period.

JWKS and TLS upstream connections verify certificate chains and endpoint identity. The default trust bundle is `/etc/ssl/certs/ca-certificates.crt`. A configured CA replaces system trust. DNS identities use SNI and hostname validation. IP upstreams use IP Subject Alternative Name validation. Kubernetes CA ConfigMaps are mounted under `/etc/auth-gateway-ca`; a changed CA bundle requires a rollout.

Upstreams use HTTP/1 unless `http_protocol: http2` is set. HTTP/2 connection options are emitted only for explicit HTTP/2 configuration. Circuit-breaker values control cluster limits; a nonzero retry breaker does not add a retry policy.

## Kubernetes files and reloads

The Envoy bootstrap and SDS resource files are projected from the main ConfigMap. TLS Secrets are mounted as read-only directories without `subPath`, so Kubernetes can refresh their projected files. Identical Secret and path bindings share a volume mount; different server chains keep separate SDS resources. File-only generation returns those SDS files but does not create or mount the certificate material.

When mappings exist, the generator puts `processing.yaml` in the separate processing ConfigMap and mounts it at `/etc/auth-gateway/processing`. Envoy reads it with file-based Extension Config Discovery Service (ECDS) and watches the mounted directory. Updating mapping values changes only that ConfigMap. The bootstrap, Deployment template, and Pod identity remain unchanged.

SDS reloads updated downstream certificates and keys for new TLS connections. ECDS reloads mapping configuration. Routes, providers, other bootstrap data, deployment settings, and upstream/JWKS CA bundles require the documented regeneration and rollout steps. The generator does not add a checksum annotation.

## Timeouts, overload, logs, and metrics

Listener defaults include a `5s` request-header timeout, `30s` request timeout, `60s` connection and stream idle timeouts, and `30s` maximum stream duration. API and route values override independently. Route values take precedence over API values. Response timeout defaults to `30s`; omitted idle and maximum stream duration values inherit from the listener. Current duration settings must be at least `1ms`.

The request-control filter strips client-supplied Envoy timeout and retry headers. The generator does not infer worker count from CPU limits. When `kubernetes.envoy_concurrency` is omitted, Envoy selects its worker count.

Overload protection is opt-in. Its fixed heap monitor and global downstream-connection monitor use the configured budgets. The default heap-shrink threshold is `0.90`; the default request-reject threshold is `0.95`. Kubernetes generation requires the heap budget to be below the Envoy memory limit.

The Envoy access logger writes structured JSON to stdout for HTTP responses with status `400` or higher. The Kubernetes metrics sidecar scrapes `127.0.0.1:9901/stats/prometheus` every `30s` by default, with a `10s` timeout, and exposes metrics at `/metrics` on port `8889`. The Envoy admin endpoint stays on loopback and is not published by the Service.
