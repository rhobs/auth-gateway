# Envoy behavior and deployment

This page describes request handling and configuration reloads. See the
[README](../README.md) for library usage and the
[configuration reference](configuration-reference.md) for supported YAML
fields.

## Listener and routes

One listener serves all configured hosts on port `8080` by default. HTTP hosts
share a filter chain. HTTPS hosts select a certificate using TLS SNI, then
match the exact HTTP `Host` or `:authority` value. A successful TLS handshake
does not grant access to a host's routes. HTTPS hosts selecting an mTLS
authenticator validate client certificates against its configured CA bundle.
Certificate-only and `all_of` servers require a client certificate during the
handshake; mixed `any_of` servers allow clients to connect without one.

Each host exposes only its listed APIs. API bindings and routes keep their
declared order. Routes match an exact path, prefix, or RE2 expression and can
rewrite the path. A known path with an unsupported method returns `405` with
an `Allow` header. An unknown host or path returns `404`.

Upstreams use HTTP/1 unless `http_protocol: http2` is set. HTTP/2 connection
options apply only when HTTP/2 is enabled. TLS upstreams verify both the
certificate chain and the configured DNS or IP identity. A custom
`trusted_ca` replaces Envoy's system CA bundle. Kubernetes output can use a
ConfigMap reference or an absolute filename for a CA file that already exists
in the Envoy container. File-based output uses an absolute filename.

## Authentication and request handling

Envoy validates JWT signatures, issuer, expiry, and `nbf`; configured
`audiences` are also checked. Each issuer has isolated claim metadata. The
API-key filter validates the configured header against the complete
Secret-backed credential set.

For mixed `authentication.any_of`, a verified JWT takes precedence when both
credentials are present, followed by a verified client certificate and then an
API key. If a higher-priority credential is absent or invalid, Envoy can try
the next method. An authenticated identity without an authorization grant is
denied without trying a lower-priority credential. `all_of` requires every
selected credential. Shared attributes must be nonempty scalar strings with
equal original values. Invalid credentials return `401`; authenticated
requests without a matching grant return `403`.

Authorization checks the original claim, key credential, or source-header
value. Attribute mappings change values used for upstream headers and metric
labels, not grant decisions. A missing value needed by a request-header mapping
is denied before the upstream request. Envoy replaces caller values for
managed output headers and removes bearer tokens, API keys, and internal
identity headers before forwarding.

## Files and reloads

File-based deployments must place generated resources at the paths Envoy reads:

| Resource                                        | Path                                           |
|-------------------------------------------------|------------------------------------------------|
| Bootstrap                                       | `/etc/auth-gateway/envoy.yaml`                 |
| Attribute mapping ECDS resource, when used      | `/etc/auth-gateway/processing/processing.yaml` |
| Downstream TLS SDS resource for each HTTPS host | `/etc/auth-gateway/server-certificate-N.yaml`  |
| Client CA SDS resource for each used mTLS authenticator | `/etc/auth-gateway/client-ca-N.yaml` |
| API-key ECDS resource, when keys are used       | `/etc/auth-gateway/api-keys/api-keys.yaml`     |
| Custom CA bundle                                | Configured absolute path                       |

File-based output does not include downstream certificates, private keys, API
keys, or custom CA bundles. Provide those files with the configured names and
permissions. Kubernetes output creates the Envoy Deployment and its ConfigMaps,
but TLS Secrets, the API-key Secret, and CA ConfigMaps remain external and must
exist in the gateway namespace. See the [API-key guide](auth/api-key.md) for
the Secret format and the [mTLS guide](auth/mtls.md) for client CA setup.

Kubernetes mounts TLS Secrets, API-key Secrets, and client CA ConfigMaps as
projected directories without `subPath`, so Envoy can observe valid changes
without replacing the Pod. SDS reloads downstream certificates and client CA
validation for new connections. ECDS reloads the complete API-key set and
mapping tables. Setting a valid empty API-key credential list revokes all keys.
Envoy keeps the last accepted resource after a failed update.

Mapping updates change only the separate `<name>-processing` ConfigMap. The
bootstrap, Deployment template, and Pod identity stay the same. Changes to
routes, authentication, authorization, request-header bindings, metric
bindings, or other bootstrap data require a Deployment rollout. Changes to
upstream or JWKS CA bundles require a rollout. Client CA ConfigMap updates are
watched and take effect on new TLS connections. Collector ConfigMap changes
require restarting the collector so it reads the new settings. Generated
Deployments have no checksum annotation.

Envoy's validation mode checks the bootstrap, but does not validate the
file-backed API-key ECDS resource. Generate API-key Secrets from validated
credentials rather than editing `api-keys.yaml` by hand.

Envoy exports native update-failure counters for ECDS and SDS. The generated
Collector exposes these counters at `/metrics`; production alerting is tracked
in [resource update monitoring](resource-update-monitoring.md).

## Timeouts and overload protection

Listener defaults include a `5s` request-header timeout, `30s` request timeout,
`1m` connection and stream idle timeouts, and a `30s` maximum stream duration.
API and route overrides apply independently; route values take precedence.
The response timeout defaults to `30s`. Missing idle and stream-duration
values inherit from the listener. Client-supplied Envoy timeout and retry
headers are removed.

Overload protection is disabled unless `overload` is configured with both a
heap budget and a downstream connection limit. Its default heap-shrink and
request-reject thresholds are `0.90` and `0.95`. For Kubernetes output, the
heap budget must be below the Envoy container memory limit. Envoy chooses its
worker count unless `kubernetes.envoy_concurrency` is set.

## Logs, metrics, and traces

Envoy writes structured JSON access logs to stdout for responses with status
`400` or higher. When metrics are enabled, the Collector scrapes Envoy's
loopback admin endpoint at `127.0.0.1:9901/stats/prometheus` and exposes
Prometheus metrics on port `8889`. The admin endpoint is not exposed by the
Service. Metrics collection is enabled by default; disabling it does not
disable per-API counters.

Each API with `metrics` configured counts responses by API and exact
downstream status. `metrics: {}` enables the counter without attribute labels.
The counter includes authentication and authorization denials, but excludes
gateway `404` and `405` fallback routes. Missing or unsafe label values become
`__unattributed__`. Envoy adds the `envoy_http_lua_` prefix; the Collector
removes it before exposing the configured metric name. Label combinations
remain in memory until Envoy restarts, so use bounded values.

Tracing is disabled by default. When enabled, Envoy sends sampled OTLP/gRPC
spans to the local Collector on `127.0.0.1:4317`. The Collector exports to the
configured `host:port` endpoint with TLS by default. Set `insecure: true` only
for a trusted plaintext endpoint. The receiver is local to the Pod and is not
exposed by the Service.
