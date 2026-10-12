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
| `authenticators`         | list of objects | Empty          | Names must be unique. Each entry sets exactly one of `jwt` or `api_key`. |
| `authorization_policies` | list of objects | Empty          | Policy names must be unique.                                             |
| `processing`             | list of objects | Empty          | Processor names must be unique.                                          |
| `servers`                | list of objects | None           | Required; at least one server.                                           |
| `apis`                   | list of objects | None           | Required; at least one API.                                              |
| `observability`          | object          | Defaults below | Optional metrics and tracing settings.                                   |
| `kubernetes`             | object          | None           | Omit for file-based output; required to generate Kubernetes resources.   |

Names used for APIs, authenticators, authorization policies, and processors
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
| `apis[].admission_control` | object          | Disabled                 | Optional per-API Envoy admission control; see [API admission control](#api-admission-control). |
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

Each configured API emits one request counter. The automatic `api` label is
the API name, and `http_status_code` comes from the response. Additional labels
use values from authenticator attributes declared under
`authenticators[].attributes`.

| Field                   | Type                                | Default | Constraint                                                                                                                                                                                                                  |
|-------------------------|-------------------------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `apis[].metrics.labels` | map of label name to attribute name | Empty   | Label names must be valid Prometheus names, must not start with `__`, and cannot be `api`, `http_status_code`, or `envoy_http_conn_manager_prefix`. Each value must be a valid attribute name declared by an authenticator. |

### API admission control

Set `apis[].admission_control.enabled: true` to apply Envoy admission control
to every route in that API. Omit the block or leave `enabled` false to keep
that API out of admission control, including when it shares a server with an
enabled API. Omitted tuning fields keep Envoy's defaults. By default, HTTP
responses below status `500` count as successes; gRPC uses Envoy's default
success status codes.

| Field                                           | Type     | Default  | Constraint                                                               |
|-------------------------------------------------|----------|----------|--------------------------------------------------------------------------|
| `apis[].admission_control.enabled`             | boolean  | `false`  | Set to `true` to enable the filter for this API.                         |
| `apis[].admission_control.sampling_window`      | duration | `30s`    | At least `1ms`; Envoy rounds the window to the nearest second.            |
| `apis[].admission_control.sr_threshold`         | number   | `95`     | Percentage from `0` to `100`; rejection probability rises below it.     |
| `apis[].admission_control.rps_threshold`        | uint32   | `0`      | When average requests per second is below this value, requests are not rejected. |
| `apis[].admission_control.max_rejection_probability` | number | `80` | Percentage from `0` to `100`; caps the rejection probability.           |

### Route processing

| Field                                                         | Type            | Default | Constraint                                                                                                                                  |
|---------------------------------------------------------------|-----------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `apis[].routes[].processing.request_headers`                  | list of objects | None    | If `processing` is present, at least one mapping is required. Requires server authentication that provides each referenced attribute.       |
| `apis[].routes[].processing.request_headers[].name`           | string          | None    | Required valid HTTP header name; cannot be a reserved identity, routing, connection, or framing header. Names must be unique ignoring case. |
| `apis[].routes[].processing.request_headers[].from_attribute` | string          | None    | Required valid attribute name.                                                                                                              |

## Servers, authentication, and authorization

| Field                      | Type            | Default | Constraint                                                                                            |
|----------------------------|-----------------|---------|-------------------------------------------------------------------------------------------------------|
| `servers[].hostname`       | string          | None    | Required exact DNS hostname; unique among servers.                                                    |
| `servers[].tls_config`     | object          | None    | Omit for HTTP; set for HTTPS. See [server TLS](#server-tls).                                          |
| `servers[].authentication` | object          | None    | Omission makes the server public. If present, set exactly one of `any_of` or `all_of`.                |
| `servers[].authorization`  | object          | None    | Optional policy selection; requires `authentication` and sets exactly one of `any_of` or `all_of`.    |
| `servers[].apis`           | list of strings | Empty   | API names bound to this server; each name must exist and appear once. An empty list serves no routes. |

For authentication and authorization selections, the chosen list must contain
at least one existing name and cannot contain duplicates. `any_of` accepts a
request when one selected method or policy succeeds; `all_of` requires every
selected entry. An `all_of` selection allows at most one JWT authenticator.
Selected JWT authenticators must have distinct issuer values.

| Field                             | Type            | Default | Constraint                                                        |
|-----------------------------------|-----------------|---------|-------------------------------------------------------------------|
| `servers[].authentication.any_of` | list of strings | None    | Selects authenticators; mutually exclusive with `all_of`.         |
| `servers[].authentication.all_of` | list of strings | None    | Selects authenticators; mutually exclusive with `any_of`.         |
| `servers[].authorization.any_of`  | list of strings | None    | Selects authorization policies; mutually exclusive with `all_of`. |
| `servers[].authorization.all_of`  | list of strings | None    | Selects authorization policies; mutually exclusive with `any_of`. |

### Server TLS

| Field                              | Type          | Default                                                                          | Constraint                                                                                                                                        |
|------------------------------------|---------------|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `servers[].tls_config.secret`      | string        | None                                                                             | Required for Kubernetes output; must name an existing TLS Secret in the gateway namespace.                                                        |
| `servers[].tls_config.certificate` | absolute path | `/etc/auth-gateway-tls/tls.crt`, or `/etc/<secret>/tls.crt` when `secret` is set | Must be a clean absolute file path other than `/`; cannot contain CR, LF, or NUL.                                                                 |
| `servers[].tls_config.private_key` | absolute path | `/etc/auth-gateway-tls/tls.key`, or `/etc/<secret>/tls.key` when `secret` is set | Same directory as `certificate`, with a different file name; must be a clean absolute file path other than `/` and cannot contain CR, LF, or NUL. |

### Authenticators

| Field                                                | Type                            | Default          | Constraint                                                                                                                      |
|------------------------------------------------------|---------------------------------|------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `authenticators[].name`                              | string                          | None             | Required unique name using the format above.                                                                                    |
| `authenticators[].jwt`                               | object                          | None             | Set exactly one of `jwt` or `api_key`.                                                                                          |
| `authenticators[].api_key`                           | object                          | None             | Set exactly one of `jwt` or `api_key`; only one API-key authenticator is supported per configuration.                           |
| `authenticators[].attributes`                        | map of attribute name to object | Empty            | Attribute keys use the format above. Each source sets exactly one supported input for its authenticator type.                   |
| `authenticators[].jwt.issuer`                        | string                          | None             | Required nonempty issuer identifier without surrounding whitespace, CR, LF, or tab.                                             |
| `authenticators[].jwt.jwks`                          | object                          | None             | Required JWKS endpoint and optional fetch settings.                                                                             |
| `authenticators[].jwt.audiences`                     | list of strings                 | Empty            | Optional; each value must be nonempty, trimmed, unique, and contain no CR, LF, or tab.                                          |
| `authenticators[].jwt.jwks.uri`                      | string                          | None             | Required absolute HTTPS URL with a valid DNS or IP host and optional port from `1` to `65535`; no user information or fragment. |
| `authenticators[].jwt.jwks.cache_duration`           | duration                        | `5m`             | Positive.                                                                                                                       |
| `authenticators[].jwt.jwks.fetch_timeout`            | duration                        | `5s`             | Positive.                                                                                                                       |
| `authenticators[].jwt.jwks.connect_timeout`          | duration                        | `5s`             | Positive; cannot exceed `fetch_timeout`.                                                                                        |
| `authenticators[].jwt.jwks.trusted_ca`               | object                          | System CA bundle | Optional replacement CA bundle; see [trusted CA](#trusted-ca).                                                                  |
| `authenticators[].jwt.jwks.circuit_breakers`         | object                          | Defaults above   | Optional; circuit-breaker defaults are still applied when omitted.                                                              |
| `authenticators[].api_key.secret`                    | string                          | None             | Required for Kubernetes output; must be a Kubernetes Secret name. Optional for file-based output.                               |
| `authenticators[].api_key.header`                    | string                          | `X-API-Key`      | Safe HTTP header name; no `_` and no reserved header names.                                                                     |
| `authenticators[].attributes.<attribute>`            | object                          | None             | Dynamic key is an attribute name.                                                                                               |
| `authenticators[].attributes.<attribute>.claim_path` | list of strings                 | None             | JWT only; one or more nonempty literal object keys.                                                                             |
| `authenticators[].attributes.<attribute>.header`     | string                          | None             | A safe request header name; no `_` or reserved identity headers. Cannot equal the API-key credential header.                    |
| `authenticators[].attributes.<attribute>.credential` | boolean                         | None             | API-key only; if set, must be `true`.                                                                                           |

An attribute source uses `claim_path` or `header` for JWTs, and `credential:
true` or `header` for API keys. Header names follow HTTP field-name syntax and
cannot use reserved identity, routing, connection, or framing headers.

### Authorization policies

| Field                                                      | Type                                     | Default | Constraint                                                                                                                                                  |
|------------------------------------------------------------|------------------------------------------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authorization_policies[].name`                            | string                                   | None    | Required unique name using the format above.                                                                                                                |
| `authorization_policies[].grants`                          | list of objects                          | Empty   | Each grant allows one authenticator to access selected APIs and attribute values.                                                                           |
| `authorization_policies[].grants[].authenticator`          | string                                   | None    | Required name of an existing authenticator.                                                                                                                 |
| `authorization_policies[].grants[].apis`                   | list of strings                          | None    | Required; at least one unique existing API name.                                                                                                            |
| `authorization_policies[].grants[].attributes`             | map of attribute name to list of strings | None    | Required; at least one attribute provided by the selected authenticator. Each allowlist must contain unique nonempty values without surrounding whitespace. |
| `authorization_policies[].grants[].attributes.<attribute>` | list of strings                          | None    | Attribute name must be valid and provided by the selected authenticator; at least one unique nonempty allowed value without surrounding whitespace.         |

## Attribute processing

| Field                                          | Type                                  | Default | Constraint                                                                                                                                                                 |
|------------------------------------------------|---------------------------------------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `processing[].name`                            | string                                | None    | Required unique processor name using the format above.                                                                                                                     |
| `processing[].type`                            | string                                | None    | Required; currently only `attribute-mapper` is supported.                                                                                                                  |
| `processing[].attributes`                      | map of attribute name to object       | Empty   | Dynamic keys use the attribute name format above.                                                                                                                          |
| `processing[].attributes.<attribute>.mappings` | map of source string to target string | Empty   | Keys and values must be nonempty and have no surrounding whitespace. Values cannot contain CR, LF, or NUL. Each mapping is an exact lookup; unmatched values pass through. |

## Trusted CA

Trusted CA settings appear under `apis[].upstream.tls_config.trusted_ca` or
`authenticators[].jwt.jwks.trusted_ca`. Omit the object to use the system CA
bundle. If present, set exactly one of `filename` or `config_map`.

| Field                        | Type          | Default | Constraint                                                                          |
|------------------------------|---------------|---------|-------------------------------------------------------------------------------------|
| `trusted_ca.filename`        | absolute path | None    | File-based output only; clean absolute path other than `/`, without CR, LF, or NUL. |
| `trusted_ca.config_map`      | object        | None    | Kubernetes output only; selects a key from a ConfigMap in the gateway namespace.    |
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
| `kubernetes.name`                       | string                                  | None                                           | Supply a valid Kubernetes resource name; used for the Deployment, Service, and related resource names.                                                                                      |
| `kubernetes.namespace`                  | string                                  | None                                           | Supply an existing Kubernetes namespace name.                                                                                                                                               |
| `kubernetes.image`                      | string                                  | `config.DefaultEnvoyImage`                     | Empty or omitted uses the Go default. Set a nonempty image override without spaces, tabs, or line breaks.                                                                                   |
| `kubernetes.otel_collector_image`       | string                                  | `config.DefaultOTelCollectorImage`             | Empty or omitted uses the Go default. Set a nonempty collector override; when metrics or tracing is enabled, it cannot contain whitespace.                                                  |
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

## API-key credential document

This separate YAML document defines the API-key Secret contents. It must
contain exactly one document and use only the fields below. An empty
`credentials` list revokes all keys.

| Field                      | Type                            | Default | Constraint                                                                                                                                                                                         |
|----------------------------|---------------------------------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `credentials`              | list of objects                 | None    | Required; `[]` is valid.                                                                                                                                                                           |
| `credentials[].key`        | string                          | None    | Required; unique nonempty HTTP header value without surrounding whitespace or control characters.                                                                                                  |
| `credentials[].attributes` | map of attribute name to string | Empty   | Attribute names must be declared as `credential: true` by the API-key authenticator. Values must be nonempty HTTP header values without surrounding whitespace, control characters, or semicolons. |

See the [API-key guide](auth/api-key.md) for the Secret layout and client
requests, and [config.example.yaml](../config.example.yaml) for a full gateway
configuration.
