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

Authorization, upstream headers, and metric labels use values from the declared
attribute sources. Supply separate source attributes when these uses need
different values. A missing value needed by a request-header binding
is denied before the upstream request. Envoy replaces caller values for
managed output headers and removes bearer tokens, API keys, and internal
identity headers before forwarding.

### Attribute flow

Envoy keeps source values in per-request dynamic metadata: `jwt_authn` provides
verified JWT claims, while `header_to_metadata` captures configured request
headers and values emitted by the API-key and mTLS filters. The native
`set_filter_state` filter first records the chosen authenticator for mixed
`any_of` requests. It copies attributes only from that identity, leaving its
missing, empty, and undeclared values unset. Lower-priority credentials cannot
fill those values. For `all_of`, every required identity can contribute
attributes after shared original values have been checked for equality.

The filter uses CEL to copy source values into
`auth_gateway.attributes.<name>`. Its configuration is part of the static
bootstrap. RBAC evaluates grants against source metadata; filter state feeds
managed upstream headers and metric labels with the same values.

## Files and reloads

File-based deployments must place generated resources at the paths Envoy reads:

| Resource                                        | Path                                           |
|-------------------------------------------------|------------------------------------------------|
| Bootstrap                                       | `/etc/auth-gateway/envoy.yaml`                 |
| Downstream TLS SDS resource for each HTTPS host | `/etc/auth-gateway/server-certificate-N.yaml`  |
| Client CA SDS resource for each mTLS host       | `/etc/auth-gateway/client-ca-N.yaml`           |
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
validation for new connections. ECDS reloads the complete API-key set.
Setting a valid empty API-key credential list revokes all keys.
Envoy keeps the last accepted resource after a failed update.

Changes to routes, authentication, authorization, attribute sources,
request-header bindings, metric bindings, or other bootstrap data require a
Deployment rollout. Changes to upstream or JWKS CA bundles require a rollout.
Client CA ConfigMap updates are watched and take effect on new TLS connections.
Collector ConfigMap changes require restarting the collector so it reads the
new settings. Generated Deployments have no checksum annotation.

Kubernetes gateway selectors use `kubernetes.name`, independently of
`node.cluster`, so separately named gateways in one namespace select distinct
Pods. See [selector upgrades](configuration-reference.md#gateway-identity-and-selector-upgrades)
before replacing resources generated with the earlier cluster-based labels.

Envoy's validation mode checks the bootstrap, but does not validate the
file-backed API-key ECDS resource. Generate API-key Secrets from validated
credentials rather than editing `api-keys.yaml` by hand.

Envoy exports native update-failure counters for ECDS and SDS. The generated
Collector exposes these counters at `/metrics`; production alerting is tracked
in [resource update monitoring](resource-update-monitoring.md).

### Upgrading after attribute mapping removal

The former top-level `processing` block is no longer accepted. Supply any
different upstream value as an additional JWT claim, API-key credential
attribute, or permitted source header. Declare that source beside the
authenticator and reference it in the route's `from_attribute` or the API's
metric labels. Route-level `processing.request_headers` remains supported.

Remove the top-level block, regenerate and apply the gateway resources, and
explicitly roll out the Deployment. After the new Pods are ready, delete the
obsolete `<name>-processing` ConfigMap. File-based deployments can delete the
old `processing/processing.yaml` after restarting Envoy with the new bootstrap.

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

### Per-API admission control

Enable `apis[].admission_control` separately for each API that needs load
shedding. Each HTTP connection manager contains one native Composite filter
with a named chain for each enabled API bound to that manager. Every chain
contains its own native AdmissionControl configuration and success-rate
history. Routes contain only a direct CompositePerRoute selector: its
`matcher.on_no_match` action selects the API's chain by name after routing has
already matched the path and method. AdmissionControl itself is never placed
in route configuration. Disabled APIs and generated `404`/`405` fallbacks have
no selector, and the Composite filter has no default action.

All routes of an API within one manager share its controller. Controllers
are separate across APIs, HTTP managers, and Envoy workers. This keeps Loki
failures from changing admission decisions for Thanos, even on a shared
hostname. Envoy's built-in admission counters may be summed within an HTTP
manager; the controllers use their own histories rather than those counters.
Additional per-API admission metrics are not generated.

The admission filter runs after authentication, authorization, and request
processing, before the router. It observes backend HTTP errors and the `503`
responses Envoy generates for upstream connection failures. Admission
rejections return `503` with `denied_by_admission_control` in the error access
log, never reach the backend, and are excluded from the failure history.

Admission settings and selectors are static bootstrap data. Regenerate and
apply the gateway resources, then explicitly roll out the Envoy Deployment
after changing them. The generated Deployment has no checksum annotation.
Move any former top-level `admission_control` block manually into the APIs
that need it; the schema stays at version `1`. See the
[configuration reference](configuration-reference.md#admission-control).

## Fault injection

Per-API `fault_injection` can abort a whole-number percentage of requests with
an HTTP error status. The fault filter runs first in each HTTP filter chain, as
Envoy requires, and route-level settings select the enabled APIs. It uses a
fixed status and percentage; clients cannot choose faults through request
headers. Unconfigured APIs and fallback routes continue normally.

An injected abort happens before authentication, attribute extraction, and
upstream forwarding. The response still passes through the per-API response
counter, so a configured counter records the injected status. Labels sourced
from authenticated attributes are `__unattributed__` for these replies. Error
access logs identify them with `fault_filter_abort` in
`response_code_details`.

Fault settings live in the bootstrap ConfigMap. Enabling, changing, or
disabling them requires regenerating and applying the gateway resources and
explicitly rolling out the Envoy Deployment. The generated Deployment has no
checksum annotation and does not restart when only that ConfigMap changes.

## Logs, metrics, and traces

Envoy writes structured JSON access logs to stdout for responses with status
`400` or higher. The `path` field omits the query string and uses the original
request path when a route rewrites it. The gateway removes client-supplied
`x-envoy-original-path` headers. Envoy then adds that header on rewritten routes
and forwards it upstream with the query string; the access log omits the query.
When metrics are enabled, the Collector scrapes Envoy's
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
