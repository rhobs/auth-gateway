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
Dedicated mTLS servers always require a trusted client certificate during the
handshake, using native `require_client_certificate: true`. Every bound API
inherits this authentication, and additional API-level methods are rejected.

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

Each server/API binding expands its original-header selectors into native
exact-match routes. List selectors produce repeated routes for the allowed
values. Each route selects its JWT requirement or enables the native API-key
filter and supplies its own RBAC grants. Authentication is disabled by default
and enabled only on selected routes. Public APIs require an explicit binding.
Unmatched access returns `403`; `404` and `405` fallbacks do not authenticate.

There is one selected credential type per entry. Multiple JWT providers use a
native JWT `requires_any` requirement, with provider-specific verified metadata
and grants. Another credential type never acts as a fallback or fills missing
attributes. Invalid selected credentials normally return `401`; the pinned
Envoy version returns `403` for an untrusted JWT audience. A valid identity
without a matching grant returns `403`.

A native RBAC CEL guard checks `request.headers`, where Envoy joins repeated
values with commas. It rejects ambiguous selectors and selected credential
headers before authentication. A short-lived internal header marks
this guard so its local denials map to `400`. Input sanitization overwrites the
marker, and it is removed after validation. Repeated selectors cannot select
another access entry or reach the backend.

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
`set_filter_state` filter is disabled by default and enabled per selected
access route. Each route carries its own extraction settings and copies
attributes only from its verifying provider. Missing, empty, or undeclared
values stay unset. Another credential never
contributes values. RBAC checks `equals` and `in` against scalar string metadata.
Equality uses a native RBAC CEL condition and nonempty scalar guards for both
source values, including request-header metadata captured before mutation.

For API keys, `header_to_metadata` records a fixed verified identity marker
from the native authentication filter's client header. Per-route API-key
configuration explicitly retains client forwarding and credential hiding.
Each credential attribute uses a separate extraction regex containing only its own name, so
adding attributes does not increase the size of existing regexes. Credential
values must be shorter than Envoy's 8 KiB metadata value limit; the combined
client header may exceed that size because it is not stored as one metadata
value. Missing bindings remain unset, and credentials and the internal
client header are removed before forwarding.

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

Generated Pods meet Kubernetes restricted Pod Security Admission requirements.
Both containers run without root, privilege escalation, Linux capabilities,
or a writable root filesystem, and use the runtime's default seccomp profile.
See [Pod security and OpenShift](configuration-reference.md#pod-security)
for image requirements and the OpenShift UID adjustment.

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
See the
[configuration reference](configuration-reference.md#admission-control).

## Fault injection

Per-API `fault_injection` can abort a whole-number percentage of requests with
an HTTP error status. A Composite filter selects one API's native fault filter
after authentication, attribute extraction, authorization, and request-header
processing. It runs before admission control and the router.

Optional exact header matches gate injection. Attribute selectors read the
same filter state as header forwarding and metrics, populated from verified
claims, API-key credentials, or certificate SANs. All configured selectors
must match, with alternative allowed values within each attribute. Header
sources cannot supply attribute selectors. Status and percentage remain
configured by the operator; Envoy's client-controlled abort headers are not
enabled. Unconfigured APIs and fallback routes have no fault selector.

Injected aborts do not reach the upstream. The standard per-API response
counter records each reply once using its status and authenticated attribute
labels, just as it records a backend reply. SLOs using this counter need no
special handling for injected failures. Error access logs identify aborts
with `fault_filter_abort` in `response_code_details`. See
[SLO accounting](fault-injection.md#slo-accounting).

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
removes it before exposing the configured metric name. Each distinct label
combination remains in memory until Envoy restarts, including combinations
from denied requests. The gateway does not enforce a cardinality limit;
configuration authors must choose bounded label values. See
[metric cardinality](configuration-reference.md#metric-cardinality) for
guidance on label selection and counter allocation.

Tracing is disabled by default. When enabled, Envoy sends sampled OTLP/gRPC
spans to the local Collector on `127.0.0.1:4317`. The Collector exports to the
configured `host:port` endpoint with TLS by default. Set `insecure: true` only
for a trusted plaintext endpoint. The receiver is local to the Pod and is not
exposed by the Service.
