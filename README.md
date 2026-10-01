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

## Current config and tests

The `config` package loads one strict YAML document, applies defaults, and
validates it. It generates Envoy config and Kubernetes resources. See
[config.example.yaml](config.example.yaml).

Each API entry defines one upstream and must include one or more routes. A
route must list one or more HTTP methods and match an exact path, a prefix, or
an Envoy safe RE2 regular expression against the full path. A route with no
methods is a configuration error. Rewrites are optional; use path, prefix, or
regular expression rewrites when the upstream path differs. Routes are checked
in the order listed, so put narrower matches first.

Run `make test` for unit tests. Run `make e2e` for the local Kind test. The e2e
test needs Docker, Kind, kubectl, and network access. It creates or reuses the
`auth-gateway-e2e` cluster and deletes its test namespace when it ends. It uses
Envoy 1.39.1 and HTTPBin 2.25.0.

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
