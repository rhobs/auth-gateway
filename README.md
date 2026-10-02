# RHOBS Auth Gateway

The goal of this project is to expose a simple API and configuration layer on top of Envoy proxy
to support common observability use cases around authentication, authorization and request transformation.

It is tailored towards the following access patterns:

1. Read and write typically have different needs from an observability perspective.
2. Within an organization, there may be a need to support varying methods of authentication and authorization for a backend.
3. The team that runs this service has full or partial control over the shape of the credentials that consume it.


This project will focus on well-defined use cases to support well known backends and APIs and will leverage
comprehensive e2e testing to ensure that the gateway fulfills these requirements.

## Why Envoy

Envoy Proxy is the foundation of this gateway. These are the reasons
for that choice:

- **Extensibility**
  - A filter chain architecture lets you add custom logic with
    [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter),
    [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter),
    and [WebAssembly](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter)
    filters.
- **Multi-method authentication**
  - Native support for
    [JWT](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter)
    and [mTLS](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl).
- **Configuration over code**
  - Define behaviour in configuration files, not in application code.
  - This produces a well-known API and a declarative, auditable configuration.
- **Observability**
  - Built-in
    [metrics](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/observability/statistics),
    [distributed tracing](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/observability/tracing),
    and [access logging](https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log).
- **Traffic management**
  - Production-grade
    [circuit breaking](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/circuit_breaking)
    and [rate limiting](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rate_limit_filter).
- **gRPC support**
  - [First-class gRPC support](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/grpc),
    including gRPC-specific load balancing and health checking.
- **Zero-downtime updates**
  - Envoy's
    [hot restart](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart)
    mechanism applies configuration and binary updates without dropping connections.
- **Red Hat product support**
  - Envoy is the data-plane proxy in Red Hat OpenShift Service Mesh.
  - Red Hat provides support, security patches, and a managed release lifecycle.
- **Mature ecosystem**
  - Envoy is a CNCF graduated project with broad adoption and a proven production track record.




## Writing Observability Data

Writing data is typically a service-to-service operation.

If we control the client credentials, we can use a simple authentication and
authorization model. Anyone with valid credentials can write data, and those
credentials are not shared with other tenants. We can use part of the
credentials to identify the tenant and add that value to the request headers.
The backend can then use that header to determine which tenant owns the data.

This makes it easier to onboard multiple tenants or teams within an
organization without managing complex authorization policies. It also lets us
make runtime decisions about how data is routed and processed on the backend.
This keeps us free from any specific tenancy model, which we consider more of
a query-time concern than a write-time concern.

## Configuration
The `config` package loads one strict YAML document, applies defaults, and
validates it. It generates Envoy config and Kubernetes resources. See
[config.example.yaml](config.example.yaml) for a complete example.
JWT configuration is shown in [config.auth.example.yaml](config.auth.example.yaml).
For protected servers, Kubernetes output stores the identity-mapping script in
its own `<name>-lua` ConfigMap as a file-based ECDS resource. Envoy watches the
projected ConfigMap directory and reloads the Lua filter when its mapping
changes, without restarting the Pod. The generator does not add a checksum to
the Deployment. Envoy still requires an explicit rolling restart for changes to
its static bootstrap, such as listeners, routes, or JWT provider settings.

Each API entry defines one upstream and must include one or more routes. A
route must list one or more HTTP methods and match an exact path, a prefix, or
an Envoy safe RE2 regular expression against the full path. A route with no
methods is a configuration error. Rewrites are optional; use path, prefix, or
regular expression rewrites when the upstream path differs. Routes are checked
in the order listed, so put narrower matches first.


## Testing

Run `make test` for unit tests. Run `make e2e` for the local Kind test. The e2e
test needs Docker, Kind, Go, curl, and network access. It downloads cmctl
v2.6.1 on first use, creates or reuses the `auth-gateway-e2e` cluster, and
deletes its test namespaces when it ends.

## Servers

The required `servers` list binds exact DNS hostnames to named APIs. Each
hostname appears once. An entry without `tls_config` serves HTTP; an entry
with `tls_config` serves HTTPS. There is no wildcard fallback.

Only APIs named in a server's `apis` list are exposed. Missing or empty
bindings serve 404 for every path. Unknown API names and repeated bindings are
configuration errors. An API can be shared by several servers or remain
unbound. The binding list sets the order between APIs, and each API keeps its
route order. Duplicate path/method matches are rejected within a server;
separate servers can expose different APIs at the same path.

HTTPS uses SNI to select a server's TLS chain. The HTTP `Host` or
`:authority` must also match that server. Set `tls_config.secret` to a
Kubernetes TLS Secret containing `tls.crt` and `tls.key`. Paths default to
`/etc/<secret>/tls.crt` and `/etc/<secret>/tls.key`. Servers can use different
Secrets or share one. Envoy's file-based SDS reloads projected certificate
updates without a Pod restart. Server TLS does not request client certificates.

All servers share one Envoy listener port (8080 by default). The generated
Service exposes port 80 when HTTP servers exist and port 443 when HTTPS servers
exist, both targeting that listener. Metrics stay on port 8889.

The TLS e2e group creates a local CA and two server certificates with
cert-manager. It checks hostname and API isolation, then uses `cmctl renew`
to renew one certificate. It verifies that Envoy serves the new certificate and
key while the other certificate and gateway Pod UID stay unchanged.

See [TLS secrets and rotation](docs/tls-secrets.md) for how Secret projection
and Envoy file-based SDS work.

## Access logging

Envoy writes structured JSON access logs to stdout for HTTP responses with a
status code of 400 or higher. Entries include the route, method, status,
duration, response details, and upstream information.

## Prometheus metrics

Generated Kubernetes resources include an OpenTelemetry Collector sidecar. It
scrapes Envoy's loopback admin endpoint at `127.0.0.1:9901/stats/prometheus`
every 30 seconds and exposes Prometheus metrics on the `metrics` port (`8889`)
of the existing `<name>` Service at path `/metrics`. The Envoy admin endpoint
stays bound to loopback and is not exposed by the Service.

The collector image defaults to
`otel/opentelemetry-collector-contrib:0.135.0`. Set
`kubernetes.otel_collector_image` to use a mirrored or different image.
