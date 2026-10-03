# JWT authentication and request processing

The gateway verifies JWTs with Envoy's native JWT filter. Server authorization
then checks the original verified claims. Optional attribute processing and
route-selected headers run only after authorization succeeds.

```text
Bearer token
  -> Verify signature, issuer, audience, expiration, and not-before
  -> Authorize using the original provider claims and selected API
  -> Populate working attributes
  -> Apply optional ordered mappings
  -> Check required route header values
  -> Set configured upstream headers
  -> Forward the request
```

## Envoy filter chain

The HTTP connection manager uses this chain when it has protected virtual
hosts. Each protected host selects its own JWT requirement and authorization
rules, keeping issuer trust and API grants scoped to that host:

```text
envoy.filters.http.jwt_authn
  -> envoy.filters.http.rbac
  -> [envoy.filters.http.set_filter_state]
  -> [auth_gateway.required_headers]
  -> [envoy.filters.http.header_mutation]
  -> envoy.filters.http.router
```

The JWT filter reads the bearer token, validates it with the configured
provider and JWKS, then stores the verified claims in authenticator-specific
dynamic metadata. The first RBAC filter authorizes the original claims and
selected API before any attribute mapping runs. The bracketed filters are
conditional: attribute initialization runs when attributes are needed,
`envoy.filters.http.set_filter_state` applies ordered mappings when configured,
and its filter configuration is loaded through file-based ECDS. Without
mappings, attribute initialization uses static filter config. The required
header check and header mutation run only when a route selects upstream
headers. Header mutation removes caller values for managed headers before
setting the verified, processed values. The router forwards the request only
after the preceding filters allow it.

## Plain JWT authorization

Each JWT authenticator names an issuer, an HTTPS JWKS endpoint, allowed
audiences, and optional claim attributes. `claim_path` is a list of literal
object keys. For example, `[organization, id]` reads
`organization.id`, while `[customer.id]` reads one top-level key named
`customer.id`.

An authorization grant names the authenticator whose claim values it accepts:

```yaml
authenticators:
  - name: metrics-jwt
    jwt:
      issuer: https://issuer.example.com
      jwks:
        uri: https://issuer.example.com/.well-known/jwks.json
      audiences: [metrics-ingestion]
      attributes:
        tenant_id:
          claim_path: [organization, id]
        writer_id:
          claim_path: [sub]

authorization_policies:
  - name: metrics-writers
    grants:
      - authenticator: metrics-jwt
        apis: [metrics-write]
        attributes:
          tenant_id: [customer-123, customer-456]

servers:
  - hostname: write.example.com
    authentication:
      any_of: [metrics-jwt]
    authorization:
      any_of: [metrics-writers]
    apis: [metrics-write]
```

The gateway accepts bearer tokens from the `Authorization` header and removes
that credential before forwarding the request. A plain JWT configuration with
no route header outputs does not add attribute-processing filters.

## JWKS transport and cache

The required `jwt.jwks` block replaces `jwt.jwks_uri`; the old key is rejected.
`cache_duration` defaults to `5m`, and `fetch_timeout` and `connect_timeout`
default to `5s`. Use positive duration strings; connect timeout must not exceed
fetch timeout. Each authenticator has a separate cluster and cache, even when
two providers use the same endpoint. Optional `circuit_breakers` uses the API
breaker defaults (1,024 connections, pending requests and requests; 0 retries).
A positive retry breaker does not create a retry policy.

JWKS connections verify both the certificate chain and the URI hostname
(or IP SAN for an IP URI). DNS identities use SNI. TLS 1.2 and 1.3 are supported.
The default trust bundle is `/etc/ssl/certs/ca-certificates.crt`. To replace it:

```yaml
jwks:
  uri: https://issuer.example.com/jwks
  cache_duration: 5m
  fetch_timeout: 5s
  connect_timeout: 5s
  trusted_ca:
    config_map: {name: issuer-ca, key: ca.crt}
```

Kubernetes references an existing CA ConfigMap in the gateway namespace and
mounts it read-only without `subPath`. File-only configurations instead accept
`trusted_ca: {filename: /etc/company/ca.crt}`. Custom bundles replace system
trust; include all required roots. CA changes require a rollout.

Fetching stays on demand, with per-worker caches. A usable cached key can
survive a temporary issuer outage. Once a needed key expires or the cache is
cold, an unavailable endpoint fails closed. Cache TTL is independent of token
expiry and does not promise immediate key revocation. Rotate with overlapping
keys and test the actual worker count and cache duration.

## Direct upstream headers

Routes choose which verified attributes become upstream headers. This example
forwards two values without translating them:

```yaml
routes:
  - methods: [POST]
    path:
      exact: /metrics/api/v1/receive
    processing:
      request_headers:
        - name: X-Scope-OrgID
          from_attribute: tenant_id
        - name: X-Writer-ID
          from_attribute: writer_id
```

Before writing these outputs, the gateway removes caller-supplied values for
every header managed by a configured route. A missing or unusable required
attribute returns 403 after authorization. A value supplied by the caller
cannot fill that gap. Other headers remain outside this route's selection.

## Ordered attribute mappings

Top-level `processing` optionally declares global attribute-mapper processors:

```yaml
processing:
  - name: upstream-tenants
    type: attribute-mapper
    attributes:
      tenant_id:
        mappings:
          customer-123: team-a
          customer-456: team-b
```

Authorization always sees the original claim value. After it succeeds, each
processor performs one exact lookup for each configured attribute. Lookup
entries in one table do not chain: if `first` maps to `second` and `second` maps
to `third`, an input of `first` becomes `second` in that processor. Unmatched
values pass through unchanged. Later processors see earlier results and may
replace them. Processor list order matters; map entry order does not. Attribute
names and values are strings.

## Multiple issuers and server isolation

A server can accept alternative authenticators with distinct issuers:

```yaml
servers:
  - hostname: write.example.com
    authentication:
      any_of: [internal-jwt, external-jwt]
    authorization:
      any_of: [writer-policy]
    apis: [metrics-write]
```

Each grant remains bound to its named authenticator. The same claim value from a
different issuer cannot use that grant or another issuer's attribute source.
Duplicate issuer bindings on one server are rejected, including bindings with
different audiences. The same issuer can be configured on separate servers.

## Missing attributes and failures

Missing, empty, null, or non-string application claims leave the corresponding
working attribute unset. They do not invalidate a JWT that otherwise passes
signature, issuer, audience, expiration, and not-before checks. An authorization
condition that needs an absent attribute does not match and access is denied.
An attribute unused by authorization and route headers can be absent without
blocking the request.

Route header checks happen after optional mappings. If a route requires an
attribute that remains absent or contains a value unsuitable for an HTTP header,
the gateway returns 403 before forwarding. Native JWT credential failures keep
Envoy's JWT filter responses. After successful authentication, unmatched paths
and methods keep their local 404 and 405 behavior.

## Mapping updates

Mapping tables are written to `processing.yaml` in a separate
`<name>-processing` ConfigMap, mounted at `/etc/auth-gateway/processing`. The
`set_filter_state` filter reads this file through Envoy's file-based ECDS and
watches the mounted directory. Updating mapping values changes the processing
ConfigMap without changing the bootstrap, Deployment template, or Pod identity.
Authorization continues to use the original claim while Envoy sends the new
mapped value upstream.

The generated Deployment does not add a checksum annotation. Static Envoy
bootstrap changes, such as route or provider changes, require a rollout to take
effect. The ECDS delivery pattern could also be evaluated for future API-key
processing, once the filter and secure key storage and rotation are defined;
API-key authentication is not implemented.

mTLS support remains future work.
