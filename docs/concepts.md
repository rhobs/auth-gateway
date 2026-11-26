# Gateway concepts

Gateway configuration defines which APIs each hostname exposes, who can use
them, and where allowed requests go. See the
[full example](../config.example.yaml) for these settings together and the
[configuration reference](configuration-reference.md) for individual fields.
See [expressions and keywords](expressions.md) for the choices available at each
layer.

## Table of contents

- [Servers](#servers)
- [APIs](#apis)
- [API bindings and access entries](#api-bindings-and-access-entries)
- [Authenticators](#authenticators)
- [Attributes](#attributes)
- [Authorization](#authorization)
- [Request processing](#request-processing)
- [Traffic protection](#traffic-protection)
- [Observability](#observability)
- [Deployment](#deployment)

## Servers

A server defines an exact hostname under `servers[]` and lists the APIs
available on that host. Servers share the configured `listener` socket.
Omitting `tls_config` selects HTTP; setting it selects HTTPS and identifies
the server certificate.

A dedicated mTLS server also selects a client-certificate authenticator through
`tls_config.mtls.authenticator`. Every API on that server inherits client
authentication.

See [server TLS settings](configuration-reference.md#server-tls) and the
[mTLS guide](auth/mtls.md) for certificate and CA setup.

## APIs

An API groups routes to one upstream backend under top-level `apis[]`. It
represents an operation, such as reading or writing a resource, so access can
be controlled for that group of routes.

Use separate APIs when operations need different access rules, even if they
share a backend. For example, `metrics-read` and `metrics-write` can point to
the same service while allowing a client to query metrics without writing them.

Each API defines:

- `routes`: HTTP methods and paths to match, with optional path rewrites.
- `upstream`: the backend address, port, protocol, and optional TLS settings.
- `attributes`: optional fixed values shared by its matching routes and server
  bindings, including public routes.

An API becomes available on a hostname when a server binds it by name. Clients
use the hostname, method, and path; API names are configuration identifiers.

See [routes and path matching](configuration-reference.md#routes-and-path-matching)
and [upstream settings](configuration-reference.md#upstream) for configuration.

## API bindings and access entries

An entry under `servers[].apis[]` binds an API to a server and defines access
rules for all of its routes on that host. The same API can be bound to several
servers with different rules.

Each binding requires protected `access` entries or explicit `public: true`.
Protected entries use `match.headers` to select a request context, such as a
tenant, then select authentication and authorization. The selector chooses
which rules apply; the request must still satisfy those rules.

Optional `fault_injection` also belongs to the binding, so each server can set
a different fault policy for the same API. See [fault injection](fault-injection.md).

See [request selection](auth/README.md#request-selection) for matching requests
to access entries and [access entry fields](configuration-reference.md#access-entries)
for configuration.

## Authenticators

Shared `authenticators[]` define how credentials are validated and which
attributes become available after verification. Defining an authenticator does
not grant access; a protected entry or mTLS server must select it.

- [JWT](auth/jwt.md) validates tokens from a configured issuer. An access entry
  can trust one or more JWT providers.
- [API keys](auth/api-key.md) validates the configured credential header against
  a set of keys and their attributes.
- [Client-certificate mTLS](auth/mtls.md) validates client certificates against
  a configured CA bundle when connecting to a dedicated HTTPS server.

JWT and API-key authentication are selected on access entries. mTLS
authentication is selected on the server. See
[authentication](auth/README.md#authentication) for how those selections work.

## Attributes

Attributes name values used in authorization, upstream headers, metric labels,
and fault selectors. Their declaration controls when they become available:

- `apis[].attributes` defines fixed values for all matching routes, including
  public routes.
- `authenticators[].attributes` defines values from verified JWT claims,
  API-key credentials, certificate SANs, original request headers, or fixed
  strings. These become available after the selected authenticator verifies
  the request.

For example, `tenant_id` can come from a verified credential while
`requested_tenant` comes from a request header. Authorization can compare them
to ensure the client is allowed to act for the requested tenant. A header
value alone does not establish the client's identity.

Fixed values can describe an API or a verified authenticator for forwarding,
telemetry, fault selection, and external authorization. Local grants require
verified credential attributes. See
[API attributes](configuration-reference.md#api-attributes) for fixed API values.

Values are used unchanged from their declared sources. Declare a separate
source attribute when another value is needed. See
[supported attribute sources](expressions.md#authenticators-and-attribute-sources),
[attribute source fields](configuration-reference.md#authenticators), and the
[JWT tenant example](auth/jwt.md#tenant-access) for configuration.

## Authorization

Each protected access entry defines `authorization`. Choose local
`authorization.grants` or delegate the decision through `authorization.ext_authz`.

Local grants name their verifying authenticator and conditions on its
attributes. Any applicable grant can allow the request; every condition within
that grant must match. A role is an attribute value you define in your
credentials and grants.

External authorization references a named service under `ext_authz_services[]`.
The service receives selected request information and returns an allow or deny
decision. It can run after local authentication or handle authentication itself.

See [grant expressions](expressions.md#authorization-grants) and
[authorization rules](auth/README.md#authorization) for local grants, and the
[external authorization guide](auth/ext-authz.md) for service setup and behavior.

## Request processing

Each route can set `processing.request_headers` to forward declared attributes
as upstream headers after authorization. The gateway replaces caller-supplied
values for those managed headers and removes credentials before forwarding.
Missing required attribute values prevent the request from reaching the backend.

Public bindings can forward fixed API attributes. Protected bindings can also
forward attributes supplied by their selected access entries.

See [forwarding](auth/README.md#forwarding) for behavior and
[route processing fields](configuration-reference.md#route-processing) for
configuration.

## Traffic protection

APIs can set upstream circuit breaker limits and enable admission control based
on their recent success rate. Top-level `overload` protects Envoy's own
resources. Listener, API, and route timeouts bound connection and request
lifetimes.

See [traffic protection](traffic-protection.md) for the scope of each control,
configuration fields, and links to Envoy's documentation.

## Observability

Top-level `observability` configures metrics collection and tracing. An API's
`metrics` block enables its response counter, with optional labels drawn from
declared attributes.

See [logs, metrics, and traces](envoy.md#logs-metrics-and-traces) for output and
[API metrics](configuration-reference.md#api-metrics) for counter settings.
For controlled errors during SLO tests, see [fault injection](fault-injection.md).

## Deployment

The library generates Envoy files and, when `kubernetes` is configured,
Kubernetes resources. Referenced TLS Secrets, API-key Secrets, and CA ConfigMaps
must be supplied separately. Static configuration changes require an explicit
Deployment rollout.

See [Kubernetes output](configuration-reference.md#kubernetes-output) for
deployment settings and [files and reloads](envoy.md#files-and-reloads) for
external resources and update behavior.
