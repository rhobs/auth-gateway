# Configuration reference

This page covers every field in the supported gateway YAML schema. Unknown
fields and documents with more than one YAML document are rejected. The
top-level `version` must be `1`.

See [config.example.yaml](../config.example.yaml) for a full configuration.
Optional settings are commented where the example uses their defaults.

Fields written as `[]` are repeated list entries. Fields written as
`<name>` are user-defined mapping keys. `None` in the Default column means the
field has no configured default. Durations are strings in Go duration syntax,
such as `250ms`, `5s`, or `1m`. Every duration in gateway configuration must
be at least `1ms`.

## Top-level fields

| Field                    | Type            | Default        | Constraint                                                               |
|--------------------------|-----------------|----------------|--------------------------------------------------------------------------|
| `version`                | integer         | None           | Required; must be `1`.                                                   |
| `node`                   | object          | Defaults below | Optional Envoy node identity.                                            |
| `listener`               | object          | Defaults below | Listener fields use the defaults below if omitted.                       |
| `overload`               | object          | Disabled       | If present, both capacity limits are required.                           |
| `authenticators`         | list of objects | Empty          | Names must be unique. Each entry sets exactly one of `jwt`, `api_key`, or `mtls`. |
| `ext_authz_services`     | list of objects | Empty          | Named gRPC authorization services; see [external authorization services](#external-authorization-services). |
| `servers`                | list of objects | None           | Required; at least one server.                                           |
| `apis`                   | list of objects | None           | Required; at least one API.                                              |
| `observability`          | object          | Defaults below | Optional metrics and tracing settings.                                   |
| `kubernetes`             | object          | None           | Omit for file-based output; required to generate Kubernetes resources.   |

Names used for APIs, authenticators, external authorization services, and shared access entries
must be 1 to 53 characters, start with a lowercase ASCII letter, and contain
only lowercase letters, digits, and hyphens. Names must be unique within their
own list. Attribute names must be 1 to 64 characters, start with a lowercase
ASCII letter, and contain only lowercase letters, digits, `_`, and `-`.

## Node and listener

| Field                                        | Type     | Default        | Constraint                                                                                                                                       |
|----------------------------------------------|----------|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `node.id`                                    | string   | `auth-gateway` | Must be nonblank after defaulting.                                                                                                               |
| `node.cluster`                               | string   | `auth-gateway` | Must be nonblank after defaulting.                                                                                                               |
| `listener.port`                              | uint32   | `8080`         | `1` to `65535`; cannot use Envoy's admin port `9901`. It also cannot conflict with enabled collector ports `8889` (metrics) or `4317` (tracing). |
| `listener.per_connection_buffer_limit_bytes` | uint32   | `1048576`      | `1` to `4294967295`.                                                                                                                             |
| `listener.max_request_headers_kb`            | uint32   | `32`           | `1` to `8192`.                                                                                                                                   |
| `listener.max_request_headers_count`         | uint32   | `100`          | `1` to `4294967295`.                                                                                                                             |
| `listener.request_headers_timeout`           | duration | `5s`           | Positive; cannot exceed `listener.request_timeout`.                                                                                              |
| `listener.request_timeout`                   | duration | `30s`          | Positive.                                                                                                                                        |
| `listener.connection_idle_timeout`           | duration | `1m`           | Positive.                                                                                                                                        |
| `listener.stream_idle_timeout`               | duration | `1m`           | Positive; default for route `idle_timeout`.                                                                                                      |
| `listener.max_stream_duration`               | duration | `30s`          | Positive; default for route `max_stream_duration`.                                                                                               |
| `listener.stream_flush_timeout`              | duration | `5s`           | Positive.                                                                                                                                        |
| `listener.tls_handshake_timeout`             | duration | `5s`           | Positive.                                                                                                                                        |
| `listener.http2`                             | object   | Envoy defaults | Optional HTTP/2 connection settings; see [HTTP/2 options](#http2-options).                                                                       |

## Overload protection

Omit `overload` to leave Envoy overload protection disabled.

| Field                                 | Type    | Default | Constraint                                                                                                                                 |
|---------------------------------------|---------|---------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `overload.max_heap_bytes`             | uint64  | None    | Required when `overload` is present; must be positive. With Kubernetes output, it must be lower than `kubernetes.resources.limits.memory`. |
| `overload.max_downstream_connections` | uint32  | None    | Required when `overload` is present; must be positive.                                                                                     |
| `overload.heap_shrink_threshold`      | float64 | `0.90`  | Finite and strictly between `0` and `1`; must be lower than `request_reject_threshold`.                                                    |
| `overload.request_reject_threshold`   | float64 | `0.95`  | Finite and strictly between `0` and `1`; must be higher than `heap_shrink_threshold`.                                                      |

## Admission control

Set `apis[].admission_control.enabled: true` to shed requests to that API when
its success rate falls below the configured threshold. Other APIs keep their
own histories, including APIs sharing the same hostname. Omit the block or
set `enabled` to `false` to leave it disabled. Generated `404` and `405`
fallback routes are excluded. Omitted tuning fields keep Envoy's defaults.
By default, HTTP responses below status `500` count as successes; gRPC uses
Envoy's default success status codes. Admission rejections return `503` and
do not reach the upstream or count as upstream failures.

| Field                                         | Type     | Default | Constraint                                                               |
|-----------------------------------------------|----------|---------|--------------------------------------------------------------------------|
| `apis[].admission_control.enabled`                  | boolean  | `false` | Enables admission control for this API's matching method routes.        |
| `apis[].admission_control.sampling_window`           | duration | `30s`   | At least `1ms`; use whole seconds for Envoy's sampling window.            |
| `apis[].admission_control.sr_threshold`              | number   | `95`    | Percentage from `0` to `100`; rejection probability rises below it.     |
| `apis[].admission_control.rps_threshold`             | uint32   | `0`     | When average requests per second is below this value, requests are not rejected. |
| `apis[].admission_control.max_rejection_probability` | number   | `80`    | Percentage from `0` to `100`; caps the rejection probability.            |

Histories are separate per API, HTTP connection manager, and Envoy worker.
Bindings of the same API within one manager share its history. Admission
monitoring counters may be summed within a manager; they do not drive
admission decisions.

The top-level `admission_control` field has been removed. Move its settings
manually into each API that needs admission control; configuration version
remains `1`. Admission settings live in the static bootstrap. Regenerate and
apply the resources, then explicitly roll out the Envoy Deployment for a
change to take effect. Generated Deployments have no checksum annotation.

## APIs, upstreams, and routes

Each API has one upstream and at least one route. API routes cannot repeat the
same method and path matcher. Routes from APIs bound to the same server also
cannot repeat a method and path matcher.

| Field                     | Type            | Default                  | Constraint                                                        |
|---------------------------|-----------------|--------------------------|-------------------------------------------------------------------|
| `apis[].name`             | string          | None                     | Required; follows the name format above.                          |
| `apis[].routes`           | list of objects | None                     | Required; at least one route.                                     |
| `apis[].upstream`         | object          | None                     | Required; see [upstream](#upstream).                              |
| `apis[].metrics`          | object          | None                     | Optional per-API counter labels; see [API metrics](#api-metrics). |
| `apis[].admission_control` | object         | Disabled                 | Optional per-API load shedding; see [Admission control](#admission-control). |
| `servers[].apis[].fault_injection` | object | Disabled | Optional HTTP error injection for this API on this server; see [Fault injection](#fault-injection). |
| `apis[].circuit_breakers` | object          | Defaults below           | Optional; omission still applies the listed defaults.             |
| `apis[].timeouts`         | object          | Effective defaults below | Optional defaults for every route in this API.                    |

### Upstream

| Field                                               | Type     | Default            | Constraint                                                                       |
|-----------------------------------------------------|----------|--------------------|----------------------------------------------------------------------------------|
| `apis[].upstream.address`                           | string   | None               | Required; a DNS name or IP address.                                              |
| `apis[].upstream.port`                              | uint32   | None               | Required; `1` to `65535`.                                                        |
| `apis[].upstream.connect_timeout`                   | duration | `5s`               | Positive.                                                                        |
| `apis[].upstream.per_connection_buffer_limit_bytes` | uint32   | `1048576`          | Must be positive.                                                                |
| `apis[].upstream.http_protocol`                     | string   | `http1`            | `http1` or `http2`.                                                              |
| `apis[].upstream.http2`                             | object   | Envoy defaults     | Optional; requires `http_protocol: http2`. See [HTTP/2 options](#http2-options). |
| `apis[].upstream.tls_config`                        | object   | None               | Optional TLS with upstream certificate verification.                             |
| `apis[].upstream.tls_config.server_name`            | string   | `upstream.address` | Optional exact DNS hostname used for TLS identity verification.                  |
| `apis[].upstream.tls_config.trusted_ca`             | object   | System CA bundle   | Optional replacement CA bundle; see [trusted CA](#trusted-ca).                   |

### Routes and path matching

| Field                                        | Type            | Default                  | Constraint                                                                                                                         |
|----------------------------------------------|-----------------|--------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `apis[].routes[].methods`                    | list of strings | None                     | Required; at least one unique supported method: `CONNECT`, `DELETE`, `GET`, `HEAD`, `OPTIONS`, `PATCH`, `POST`, `PUT`, or `TRACE`. |
| `apis[].routes[].path`                       | object          | None                     | Required; set exactly one of `exact`, `prefix`, or `regex`.                                                                        |
| `apis[].routes[].path.exact`                 | string          | None                     | Clean absolute request path; no query, fragment, backslash, or newline.                                                            |
| `apis[].routes[].path.prefix`                | string          | None                     | Nonempty clean absolute path prefix; no query, fragment, backslash, or newline. A trailing slash is accepted.                      |
| `apis[].routes[].path.regex`                 | string          | None                     | Must compile as a Go RE2 regular expression.                                                                                       |
| `apis[].routes[].rewrite`                    | object          | None                     | Optional; set exactly one of `path`, `prefix`, or `regex`.                                                                         |
| `apis[].routes[].rewrite.path`               | string          | None                     | Clean absolute request path; no query, fragment, backslash, or newline.                                                            |
| `apis[].routes[].rewrite.prefix`             | string          | None                     | Nonempty clean absolute path prefix; no query, fragment, backslash, or newline.                                                    |
| `apis[].routes[].rewrite.regex`              | object          | None                     | Pattern and replacement used to rewrite matching paths.                                                                            |
| `apis[].routes[].rewrite.regex.pattern`      | string          | None                     | Required; nonempty Go RE2 regular expression.                                                                                      |
| `apis[].routes[].rewrite.regex.substitution` | string          | `""`                     | Optional; cannot contain `?`, `#`, CR, or LF.                                                                                      |
| `apis[].routes[].processing`                 | object          | None                     | Optional per-route request header mappings; see [route processing](#route-processing).                                             |
| `apis[].routes[].timeouts`                   | object          | Effective defaults below | Optional per-route overrides, which take precedence over API-level values.                                                         |

### Route timeouts

The fields below appear under either `apis[].timeouts` or
`apis[].routes[].timeouts`. The effective response timeout defaults to `30s`;
idle and maximum stream duration default to the corresponding listener values.
Overrides apply independently: route values take precedence over API values.
Omitted timeout overrides stay unset in the parsed configuration; generated
Envoy output resolves the effective values. A response timeout cannot exceed
the effective maximum stream duration.

| Field suffix          | Type     | Default                                | Constraint                                               |
|-----------------------|----------|----------------------------------------|----------------------------------------------------------|
| `response_timeout`    | duration | `30s`                                  | Positive; cannot exceed effective `max_stream_duration`. |
| `idle_timeout`        | duration | `listener.stream_idle_timeout` (`1m`)  | Positive.                                                |
| `max_stream_duration` | duration | `listener.max_stream_duration` (`30s`) | Positive.                                                |

### HTTP/2 options

These fields appear under `listener.http2` or `apis[].upstream.http2`.
Omitted fields keep Envoy's defaults.

| Field suffix                     | Type   | Default       | Constraint               |
|----------------------------------|--------|---------------|--------------------------|
| `max_concurrent_streams`         | uint32 | Envoy default | `1` to `2147483647`.     |
| `initial_stream_window_size`     | uint32 | Envoy default | `65535` to `2147483647`. |
| `initial_connection_window_size` | uint32 | Envoy default | `65535` to `2147483647`. |

### Circuit breakers

These fields appear under `apis[].circuit_breakers` or
`authenticators[].jwt.jwks.circuit_breakers`. They are also applied when the
object is omitted.

| Field suffix           | Type   | Default | Constraint                                         |
|------------------------|--------|---------|----------------------------------------------------|
| `max_connections`      | uint32 | `1024`  | `0` to `4294967295`.                               |
| `max_pending_requests` | uint32 | `1024`  | `0` to `4294967295`.                               |
| `max_requests`         | uint32 | `1024`  | `0` to `4294967295`.                               |
| `max_retries`          | uint32 | `0`     | `0` to `4294967295`; zero disables retry capacity. |

### API metrics

Each API with `metrics` configured emits a request counter. The automatic `api`
label is the API name and `http_status_code` comes from the response.
Additional labels use values from authenticator attributes declared under
`authenticators[].attributes` or response attributes declared by an external
authorization entry.
Requests carrying both the configured API-key header and `Authorization` are
rejected before this counter runs.

| Field                   | Type                                | Default | Constraint                                                                                                                                                                                                                  |
|-------------------------|-------------------------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `apis[].metrics.labels` | map of label name to attribute name | Empty   | Label names must be valid Prometheus names, must not start with `__`, and cannot be `api`, `http_status_code`, or `envoy_http_conn_manager_prefix`. Each value must be a valid authenticator or external response attribute. |

#### Metric cardinality

Configuration authors are responsible for choosing metric labels with bounded
values. The gateway does not enforce a cardinality limit. Each distinct
combination of API, HTTP status, and attribute values creates an Envoy
counter retained until Envoy restarts. Too many combinations can cause a
cardinality explosion and exhaust gateway memory. Label length and character
checks do not bound the number of distinct values.

Use labels drawn from a small, known set of values. Avoid request IDs, raw
URLs, arbitrary header values, and unrestricted user identifiers. Consider
combinations as well as individual labels: 100 tenant values and 100 writer
values can produce 10,000 combinations for each API and status.

Denied requests can also create distinct counters when source attributes are
available. Dropping exported series or disabling collector scraping does not
prevent Envoy from allocating counters. Set `metrics: {}` to count by API and
status without attribute labels.

### Fault injection

Set `servers[].apis[].fault_injection.enabled: true` to abort a percentage of matching
requests with a configured HTTP error after authentication, authorization,
and required-header checks. Every method route of that binding is
eligible; other bindings and gateway `404`/`405` fallback routes are not. Omit the
block or set `enabled: false` to disable injection. A disabled block may keep
its abort settings for the next test.

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| `servers[].apis[].fault_injection.enabled` | boolean | `false` | Requires `abort` when enabled. |
| `servers[].apis[].fault_injection.match` | object | None | Optional; if supplied, must contain headers or attributes. Omit to select all requests that pass authentication, authorization, and required-header checks. |
| `servers[].apis[].fault_injection.match.headers` | list of match expressions | Empty | Each entry has `name`, `expression`, and a `value` for `equals` or `in`. Supports `equals`, `in`, and `present`. Names are case-insensitive, unique, and cannot contain underscores or use reserved identity, routing, connection, framing, or credential headers. Route processing cannot overwrite them. |
| `servers[].apis[].fault_injection.match.attributes` | list of match expressions | Empty | Each entry has a verified attribute `name`, `expression`, and a `value` for `equals` or `in`. Supports `equals`, `in`, and `present`. Names must be unique. Every protected access entry must provide each attribute from a verified claim, credential, certificate SAN, or external authorization result; header sources are rejected. |
| `servers[].apis[].fault_injection.abort` | object | None | Required when enabled; HTTP errors only. |
| `servers[].apis[].fault_injection.abort.http_status` | uint32 | None | Required error status from `400` to `599`. |
| `servers[].apis[].fault_injection.abort.percentage` | uint32 | None | Required whole-number percentage from `1` to `100`. |

All header and attribute selectors must match. `in` takes a nonempty list of
distinct strings; `present` omits `value`. Header presence accepts an empty
header, while attribute presence requires a nonempty verified value. Missing
attributes or headers do not match, and values are case-sensitive. Only the
entry's verifying provider supplies attributes. The configured
percentage applies after selection. Clients cannot change the configured
status or percentage through Envoy fault-control headers.

Injected requests do not reach the upstream. With `apis[].metrics` configured,
each injected reply increments the standard per-API counter once, using its
configured status and authenticated attribute labels. Backend and injected
replies with the same labels share the same series, so SLOs using this counter
apply the same status-based calculation with injection enabled or disabled. See
[SLO accounting](fault-injection.md#slo-accounting).

Fault settings are part of the static bootstrap: regenerate and apply the
gateway configuration, then explicitly roll out the Deployment to toggle them.

### Route processing

| Field                                                         | Type            | Default | Constraint                                                                                                                                  |
|---------------------------------------------------------------|-----------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `apis[].routes[].processing.request_headers`                  | list of objects | None    | If `processing` is present, at least one mapping is required. Every protected entry must provide each referenced attribute; public bindings cannot use these mappings.       |
| `apis[].routes[].processing.request_headers[].name`           | string          | None    | Required valid HTTP header name; cannot be a reserved identity, routing, connection, or framing header. Names must be unique ignoring case. |
| `apis[].routes[].processing.request_headers[].from_attribute` | string          | None    | Required valid attribute name.                                                                                                              |

Headers and metric labels use attribute values directly from their declared
sources. When an upstream needs a different value from the one used in a grant,
supply an additional source attribute and reference it in `from_attribute` or
`apis[].metrics.labels`. See the [JWT](auth/jwt.md), [API-key](auth/api-key.md),
and [external authorization](auth/ext-authz.md) guides for examples.

### External authorization services

Each `ext_authz_services[]` entry defines one gRPC Check service. Its upstream
uses HTTP/2 and verified TLS. The service must be reachable by Envoy, and a
custom CA ConfigMap must exist in the gateway namespace before deployment.

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| `ext_authz_services[].name` | string | None | Required unique name using the format above. |
| `ext_authz_services[].upstream` | object | None | Required; uses the [upstream fields](#upstream), with `http_protocol: http2` and `tls_config` required. |
| `ext_authz_services[].timeout` | duration | `300ms` | Positive gRPC Check timeout. |
| `ext_authz_services[].request_headers` | list of strings | None | Required nonempty, case-insensitive unique list of HTTP request headers sent to the service. Header names must be valid, contain no `_`, and must not be reserved identity, routing, connection, or framing headers. `authorization` and `cookie` are allowed. |
| `ext_authz_services[].credential_headers` | list of strings | Empty | Case-insensitive unique subset of `request_headers`; removed before forwarding to the API upstream. Include any credential header the service uses. |
| `ext_authz_services[].attributes` | list of objects | Empty | Declared values sent in the Check request's `auth_gateway.ext_authz.attributes` metadata namespace. Names must be unique valid attribute names. |
| `ext_authz_services[].attributes[].name` | string | None | Required attribute name. |
| `ext_authz_services[].attributes[].from_source` | string | None | `header` or `authenticator`. |
| `ext_authz_services[].attributes[].value` | string | None | For `header`, a safe `request_headers` entry that is not a credential header. For `authenticator`, the same name as an attribute declared by every selected local authenticator. |

The service receives selected headers, declared attributes, and route metadata
identifying the API and access entry. After local JWT verification, it also
receives the parsed JWT payload under `envoy.filters.http.jwt_authn`, keyed by
provider name. Declared authenticator attributes are also available after
local JWT, API-key, or mTLS authentication. Missing or non-string declared
values are omitted. The service must return an explicit allow or deny decision.
See the [external authorization guide](auth/ext-authz.md) for the Check contract
and failure behavior.

## Servers, authentication, and authorization

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| `servers[].hostname` | string | None | Required unique exact DNS hostname. |
| `servers[].tls_config` | object | None | Omit for HTTP; set for HTTPS. See [server TLS](#server-tls). |
| `servers[].apis` | list of objects | Empty | Ordered API bindings; names must exist and appear once per server. |
| `servers[].apis[].name` | string | None | Required name of an existing API. |
| `servers[].apis[].public` | boolean | `false` | Explicit public access; cannot be combined with `access`, server mTLS, or authenticated header forwarding. |
| `servers[].apis[].access` | list of objects | None | Required nonempty list unless `public: true`. |

### Access entries

The following fields live under `servers[].apis[].access[]`. An entry uses
exactly one of `tenant` (a concrete label) or `name` (a shared label). Labels
must be unique within a binding; a label does not itself match a request.

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| `tenant` | string | None | Nonempty concrete label without commas, controls, or surrounding whitespace. |
| `name` | string | None | Shared label using the name format above. |
| `match.headers` | list of expressions | Empty | All configured headers must match. Names must be safe headers without underscores or duplicates ignoring case. Credential headers are allowed only with `present` and the matching authentication method; other reserved headers are forbidden. |
| `match.headers[].name` | string | None | Required request header name. |
| `match.headers[].expression` | string | None | `equals` for one string, `in` for a list, or `present` for header existence. `equals-attribute` is not valid for headers. |
| `match.headers[].value` | string or list of strings | None | Nonempty string for `equals`; nonempty list of distinct strings for `in`; omit for `present`. Values cannot contain commas, controls, or surrounding whitespace. |
| `authentication.jwt.providers` | list of strings | None | Nonempty unique JWT authenticator names with distinct issuers within this entry; optional when `authorization.ext_authz` is selected. |
| `authentication.api_key.authenticator` | string | None | Name of the API-key authenticator. |
| `authorization.grants` | list of objects | None | Nonempty grants when local authorization is selected. See [authorization grants](#authorization-grants). |
| `authorization.ext_authz` | object | None | Selects one named external service instead of local grants. See [external authorization](#external-authorization). |

Outside dedicated mTLS servers, `authentication` selects exactly one of
`jwt` or `api_key` when local grants are used. It may be omitted for external
authorization, allowing the service to authenticate as well as authorize.
A JWT entry may trust several providers; each grant remains
tied to one verifying provider. A key cannot replace an invalid JWT on a JWT
entry, and a JWT cannot replace a missing key on a key entry.
If both the configured API-key header and `Authorization` are present, the
gateway returns `403` before authentication on every path, including public
and unmatched paths. Empty header values also count as present.

Selectors cannot overlap within a binding. `X-Tenant` values also cannot
overlap across entries even when other header selectors differ, except when
one entry requires `Authorization: present` for JWT and the other requires the
configured API-key header with `present` for API-key authentication. This lets
both methods serve the same API path and tenant. `present` matches even an
empty header value; credential validation still applies. An empty header match
is an explicit catch-all and must be the binding's only entry.
Header values are case-sensitive. Lists accept one value per request; repeated
selector or selected credential headers and comma-separated selectors return
`400`. Missing or unmatched selectors return `403`. Invalid selected
credentials normally return `401`; a validly signed JWT with an untrusted
audience returns `403` in the pinned Envoy version. An authenticated request
without an applicable grant returns `403`. External denials use the service's
HTTP status, and Check errors or timeouts return `503`. Denials do not reach
the upstream.

A public API requires `public: true`; omitted access never makes it public.
See the [authentication guide](auth/README.md) for examples.

### Server TLS

| Field                              | Type          | Default                                                                          | Constraint                                                                                                                                        |
|------------------------------------|---------------|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `servers[].tls_config.secret`      | string        | None                                                                             | Required for Kubernetes output; must name an existing TLS Secret in the gateway namespace.                                                        |
| `servers[].tls_config.certificate` | absolute path | `/etc/auth-gateway-tls/tls.crt`, or `/etc/<secret>/tls.crt` when `secret` is set | Must be a clean absolute file path other than `/`; cannot contain CR, LF, or NUL.                                                                 |
| `servers[].tls_config.private_key` | absolute path | `/etc/auth-gateway-tls/tls.key`, or `/etc/<secret>/tls.key` when `secret` is set | Same directory as `certificate`, with a different file name; must be a clean absolute file path other than `/` and cannot contain CR, LF, or NUL. |
| `servers[].tls_config.mtls` | object | None | Dedicated mTLS mode for this entire server and all bound APIs; always requires a trusted client certificate during TLS establishment. |
| `servers[].tls_config.mtls.authenticator` | string | None | Required name of an mTLS authenticator. Every API access entry must omit `authentication`, and all grants must name this authenticator. |

mTLS servers require HTTPS serving certificates and an explicit client CA.
Public bindings, optional client certificates, and additional authentication on
any bound API are configuration errors. Another server may expose the same API
with JWT or API-key entries. See the [mTLS guide](auth/mtls.md).

### Authenticators

| Field                                                | Type                            | Default          | Constraint                                                                                                                      |
|------------------------------------------------------|---------------------------------|------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `authenticators[].name`                              | string                          | None             | Required unique name using the format above.                                                                                    |
| `authenticators[].jwt`                               | object                          | None             | Set exactly one of `jwt`, `api_key`, or `mtls`.                                                                                   |
| `authenticators[].api_key`                           | object                          | None             | Set exactly one of `jwt`, `api_key`, or `mtls`; only one API-key authenticator is supported per configuration.                    |
| `authenticators[].mtls`                              | object                          | None             | Set exactly one of `jwt`, `api_key`, or `mtls`; only HTTPS servers may select it.                                                 |
| `authenticators[].jwt.issuer`                        | string                          | None             | Required nonempty issuer identifier without surrounding whitespace, CR, LF, or tab.                                             |
| `authenticators[].jwt.jwks`                          | object                          | None             | Required JWKS endpoint and optional fetch settings.                                                                             |
| `authenticators[].jwt.audiences`                     | list of strings                 | Empty            | Optional; each value must be nonempty, trimmed, unique, and contain no CR, LF, or tab.                                          |
| `authenticators[].jwt.jwks.uri`                      | string                          | None             | Required absolute HTTPS URL with a valid DNS or IP host and optional port from `1` to `65535`; no user information or fragment. |
| `authenticators[].jwt.jwks.dns_lookup_family`        | string                          | `V4_ONLY`        | Envoy DNS family: `AUTO`, `V4_ONLY`, `V6_ONLY`, `V4_PREFERRED`, or `ALL`.                                                        |
| `authenticators[].jwt.jwks.cache_duration`           | duration                        | `5m`             | Positive.                                                                                                                       |
| `authenticators[].jwt.jwks.fetch_timeout`            | duration                        | `5s`             | Positive.                                                                                                                       |
| `authenticators[].jwt.jwks.connect_timeout`          | duration                        | `5s`             | Positive; cannot exceed `fetch_timeout`.                                                                                        |
| `authenticators[].jwt.jwks.trusted_ca`               | object                          | System CA bundle | Optional replacement CA bundle; see [trusted CA](#trusted-ca).                                                                  |
| `authenticators[].jwt.jwks.circuit_breakers`         | object                          | Defaults above   | Optional; circuit-breaker defaults are still applied when omitted.                                                              |
| `authenticators[].api_key.secret`                    | string                          | None             | Required for Kubernetes output; must be a Kubernetes Secret name. Optional for file-based output.                               |
| `authenticators[].api_key.header`                    | string                          | `X-API-Key`      | Safe HTTP header name; no `_` and no reserved header names.                                                                     |
| `authenticators[].mtls.trusted_ca`                   | object                          | None             | Required explicit client CA bundle; see [trusted CA](#trusted-ca).                                                               |
| `authenticators[].attributes`                     | list of objects                 | Empty            | Each entry declares one named attribute. Names must be unique and use lowercase letters, numbers, `_`, or `-`; the first character must be a letter. |
| `authenticators[].attributes[].name`              | string                          | None             | Required attribute name used by grants, metrics, and request processing. |
| `authenticators[].attributes[].from_source`       | string                          | None             | Required source: `claim` for JWT, `credential` for API keys, `certificate` for mTLS, or `header` for any authenticator. |
| `authenticators[].attributes[].value`             | string or list of strings       | None             | A nonempty list of literal object keys for `claim`; a credential attribute name, `uri_san` or `dns_san`, or a safe HTTP request header name for the other sources. |

Each certificate may have at most one URI SAN and one DNS SAN; a SAN containing
a comma is rejected. Header names follow HTTP field-name syntax and cannot use
reserved identity, routing, connection, or framing headers. A header source
cannot equal the API-key credential header. Credential values come from the
named key in the API-key Secret and are used unchanged.

### Authorization grants

These fields live under `servers[].apis[].access[].authorization.grants[]`.
A grant already belongs to one API on one server. Any matching grant allows
access; every condition within that grant must succeed.

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| `authenticator` | string | None | Required authenticator enabled by this entry, or the server's dedicated mTLS authenticator. |
| `attributes` | list of expressions | None | JWT and key grants require at least one credential-derived condition. mTLS may use `[]` or omit the list to trust the client CA alone. |
| `attributes[].name` | string | None | Required unique attribute name declared by this authenticator; its source must be a verified claim, key credential, or certificate SAN. |
| `attributes[].expression` | string | None | `equals` compares a scalar attribute with a string, `in` checks a scalar against a configured list, `equals-attribute` compares two scalar attributes, `present` requires a nonempty scalar string, `has` checks a JWT claim list for one string, and `has-one-of` checks it for any configured string. |
| `attributes[].value` | string or list of strings | None | Omit for `present`; use a nonempty string for `equals`, `equals-attribute`, and `has`, or a nonempty list of distinct strings for `in` and `has-one-of`. Values cannot contain controls or surrounding whitespace. |

`equals` and `in` require a scalar string attribute. A list-valued JWT claim
does not match those expressions. `has` and `has-one-of` require a list-valued
JWT claim. A scalar, missing, null, or empty claim does not match. They match
exact string elements; other element types are ignored. Values are
case-sensitive and used unchanged. List claims are used directly for grants;
they are not copied into string filter state for upstream headers, metric
labels, or fault injection selectors.

`present` requires a nonempty scalar string from a verified claim, API-key
credential, or certificate SAN. Missing, empty, null, numeric, and list-valued
attributes do not match. Request header attributes cannot be grant conditions.

`equals-attribute` requires both original values to be nonempty scalar strings
and exactly equal. Missing, empty, list-valued, and non-string operands fail.
The right-hand source may be another verified attribute or a request header;
a header must participate in this entry's `match.headers`. This binds a listed
requested tenant to the particular verified tenant rather than checking two
independent allowlists. Attribute values are never normalized or translated.

### External authorization

These fields live under `servers[].apis[].access[].authorization.ext_authz`.
Select exactly one of `authorization.grants` or `authorization.ext_authz`.

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| `service` | string | None | Required name of an `ext_authz_services[]` entry. |

Local JWT or API-key authentication runs before the external check when
configured. Dedicated mTLS server authentication is inherited. With no local
authenticator, the service performs any required authentication itself.
Header attributes can feed managed upstream headers and metric labels.

## Trusted CA

Trusted CA settings appear under `apis[].upstream.tls_config.trusted_ca`,
`ext_authz_services[].upstream.tls_config.trusted_ca`, or
`authenticators[].jwt.jwks.trusted_ca`, and are required under
`authenticators[].mtls.trusted_ca`. Upstream and JWKS trust use the system CA
bundle when this object is omitted. mTLS client trust has no system CA fallback.
Set exactly one of `filename` or `config_map` when the object is present.

| Field                        | Type          | Default | Constraint                                                                          |
|------------------------------|---------------|---------|-------------------------------------------------------------------------------------|
| `trusted_ca.filename`        | absolute path | None    | Clean absolute path other than `/`, without CR, LF, or NUL; for Kubernetes output, the file must exist in the Envoy container. |
| `trusted_ca.config_map`      | object        | None    | Kubernetes output only; mounts a selected key from a ConfigMap in the gateway namespace. |
| `trusted_ca.config_map.name` | string        | None    | Required valid Kubernetes ConfigMap name.                                           |
| `trusted_ca.config_map.key`  | string        | None    | Required valid ConfigMap data key.                                                  |

## Observability

| Field                                       | Type     | Default                                    | Constraint                                                                                         |
|---------------------------------------------|----------|--------------------------------------------|----------------------------------------------------------------------------------------------------|
| `observability.metrics`                     | object   | Defaults below                             | Optional Prometheus collection settings.                                                           |
| `observability.tracing`                     | object   | Defaults below                             | Optional OpenTelemetry tracing settings.                                                           |
| `observability.metrics.enabled`             | boolean  | `true`                                     | Disables collector scraping when false; per-API Envoy counters are still generated.                |
| `observability.metrics.scrape_interval`     | duration | `30s`                                      | Positive whole number of milliseconds.                                                             |
| `observability.metrics.scrape_timeout`      | duration | `10s`                                      | Positive whole number of milliseconds; cannot exceed the scrape interval.                          |
| `observability.metrics.custom_metric_name`  | string   | `auth_gateway_http_requests_total`         | Prometheus name: ASCII letter or `_` first, then letters, digits, or `_`; cannot start with `__`.  |
| `observability.tracing.enabled`             | boolean  | `false`                                    | Enables Envoy spans and collector export when true.                                                |
| `observability.tracing.endpoint`            | string   | None                                       | Required when tracing is enabled; valid host and port from `1` to `65535`, with no CR, LF, or NUL. |
| `observability.tracing.service_name`        | string   | `node.cluster` (`auth-gateway` by default) | When tracing is enabled, cannot be empty or whitespace and cannot contain CR, LF, or NUL.          |
| `observability.tracing.sampling_percentage` | float64  | `100`                                      | Finite value from `0` to `100`, inclusive.                                                         |
| `observability.tracing.insecure`            | boolean  | `false`                                    | When true, disables TLS for the collector's OTLP connection.                                       |

## Kubernetes output

The Kubernetes section is needed only when generating Kubernetes resources
and affects the CA and API-key Secret forms described above.

Empty or omitted image values use the Go defaults below. Nonempty YAML values
are preserved, so set these fields to use approved images or private mirrors.

| Field                                   | Type                                    | Default                                        | Constraint                                                                                                                                                                                  |
|-----------------------------------------|-----------------------------------------|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `kubernetes.name`                       | string                                  | None                                           | Supply a valid Kubernetes resource name; used for resource names and the `app.kubernetes.io/instance` label in Deployment and Service selectors.                                            |
| `kubernetes.namespace`                  | string                                  | None                                           | Supply an existing Kubernetes namespace name.                                                                                                                                               |
| `kubernetes.image`                      | string                                  | `gateway.DefaultEnvoyImage`                     | Empty or omitted uses the Go default. Set a nonempty image override without spaces, tabs, or line breaks.                                                                                   |
| `kubernetes.otel_collector_image`       | string                                  | `gateway.DefaultOTelCollectorImage`             | Empty or omitted uses the Go default. Set a nonempty collector override; when metrics or tracing is enabled, it cannot contain whitespace.                                                  |
| `kubernetes.replicas`                   | int32                                   | `2`                                            | Must not be negative; zero is allowed.                                                                                                                                                      |
| `kubernetes.service_port`               | int32                                   | `80`                                           | For HTTP servers, `1` to `65535`; cannot conflict with enabled metrics port `8889`.                                                                                                         |
| `kubernetes.https_service_port`         | int32                                   | `443` when an HTTPS server exists              | Requires an HTTPS server; `1` to `65535`; cannot equal `service_port` or conflict with enabled metrics port `8889`.                                                                         |
| `kubernetes.resources`                  | object                                  | Defaults below                                 | Envoy container resources.                                                                                                                                                                  |
| `kubernetes.resources.requests`         | map of resource name to quantity string | `{cpu: 50m, memory: 64Mi}`                     | Resource names must be valid Kubernetes qualified names. Quantities must be valid and nonnegative; a request cannot exceed a matching limit. An explicit empty map disables these defaults. |
| `kubernetes.resources.limits`           | map of resource name to quantity string | `{cpu: 1, memory: 256Mi}`                      | Resource names and quantities follow the same rules as `requests`. An explicit empty map disables these defaults.                                                                           |
| `kubernetes.envoy_concurrency`          | uint32                                  | Envoy chooses                                  | If set, must be positive.                                                                                                                                                                   |
| `kubernetes.metrics`                    | object                                  | Defaults below                                 | Collector container resource settings.                                                                                                                                                      |
| `kubernetes.metrics.resources`          | object                                  | Defaults below                                 | Uses the same Kubernetes resource quantity rules.                                                                                                                                           |
| `kubernetes.metrics.resources.requests` | map of resource name to quantity string | `{cpu: 20m, memory: 64Mi}`                     | Resource names must be valid Kubernetes qualified names. Quantities must be valid and nonnegative; a request cannot exceed a matching limit. An explicit empty map disables these defaults. |
| `kubernetes.metrics.resources.limits`   | map of resource name to quantity string | `{memory: 256Mi}`                              | Resource names and quantities follow the same rules as `requests`. An explicit empty map disables these defaults.                                                                           |

The loader passes `kubernetes.name` and `kubernetes.namespace` to generated
resource metadata unchanged; Kubernetes enforces their naming rules when the
manifest is applied. Resource map defaults apply only when the entire map is
omitted or null. Supplying a partial map does not fill its missing entries.

### Pod security

Generated Pods use the `RuntimeDefault` seccomp profile. Envoy and the optional
collector require a non-root user, disable privilege escalation, drop all
Linux capabilities, and use a read-only root filesystem. These settings meet
Kubernetes restricted Pod Security Admission requirements.

Envoy runs as UID/GID `101`. The pinned collector image declares non-root
UID/GID `10001`; the Deployment leaves these fields unset for the collector.
Collector image overrides must declare a numeric non-root user, or supply one
in the generated Deployment, and work without a writable root filesystem.

Regenerate and apply the Kubernetes manifest to update existing Pod security
settings. The changed Pod template starts a Deployment rollout.

### OpenShift

OpenShift's
[`restricted-v2` SCC](https://github.com/openshift/cluster-kube-apiserver-operator/blob/main/bindata/bootkube/scc-manifests/0000_20_kube-apiserver-operator_00_scc-restricted-v2.yaml)
assigns a user ID from the namespace's allocated range. Before applying each
generated manifest, remove `runAsUser` and `runAsGroup` from the Envoy container's
`securityContext` in the Deployment. Keep `runAsNonRoot: true` and the other
security settings so the SCC can supply the namespace's user ID.

Keep the fixed Envoy UID/GID on plain Kubernetes: the pinned Envoy image's
metadata defaults to root. The collector needs no UID adjustment. OpenShift
SCC admission has not been verified against a live OpenShift cluster; the Kind
suite verifies Kubernetes restricted Pod Security Admission.

### Gateway identity and selector upgrades

Deployment selectors, Pod labels, and Service selectors use
`app.kubernetes.io/name: auth-gateway` and
`app.kubernetes.io/instance: <kubernetes.name>`. Use distinct names for gateways
in the same namespace. Changing `node.cluster` preserves these selectors and
Pod labels; apply the regenerated bootstrap and explicitly roll out the
Deployment to use the new Envoy cluster identity.

Earlier generated resources used `node.cluster` as the instance label. If
that value differs from `kubernetes.name`, the new Deployment selector changes.
Kubernetes rejects an in-place change to an existing Deployment's immutable
selector. Choose a maintenance window and recreate the Deployment before
applying the regenerated resources, for example:

```sh
kubectl -n observability delete deployment auth-gateway --cascade=foreground --wait=true
kubectl apply -f kubernetes.yaml
kubectl -n observability rollout status deployment/auth-gateway
```

This sequence interrupts gateway traffic until the replacement is ready.
Alternatively, deploy a replacement with a new `kubernetes.name`, verify it,
switch clients to its Service, then remove the old gateway resources. Choose a
replacement name distinct from existing legacy instance labels so old
selectors cannot match its Pods. If the old instance label already equals
`kubernetes.name`, the selector stays the same and recreation is unnecessary.

## API-key credential document

This separate YAML document defines the API-key Secret contents. It must
contain exactly one document and use only the fields below. An empty
`credentials` list revokes all keys.

| Field                      | Type                            | Default | Constraint                                                                                                                                                                                         |
|----------------------------|---------------------------------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `credentials`              | list of objects                 | None    | Required; `[]` is valid.                                                                                                                                                                           |
| `credentials[].key`        | string                          | None    | Required; unique nonempty HTTP header value without commas, surrounding whitespace, or control characters.                                                                                                  |
| `credentials[].attributes` | map of attribute name to string | Empty   | Attribute names must be referenced by a `credential` source value in the API-key authenticator. Values must be nonempty HTTP header values of at most 8191 bytes without surrounding whitespace, control characters, or semicolons. |

See the [API-key guide](auth/api-key.md) for the Secret layout and client
requests, and [config.example.yaml](../config.example.yaml) for a full gateway
configuration.
