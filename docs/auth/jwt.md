# JWT

## Authentication

Envoy reads `Authorization: Bearer <token>` and verifies its signature
against the configured HTTPS JSON Web Key Set (JWKS). It checks `iss`,
requires a valid `exp`, and enforces `nbf` when present. Set `audiences`
to require a matching `aud` value; omit it to skip that check. Define
one named authenticator per issuer. Declare attributes beside `jwt` to read
verified claims or incoming request headers:

```yaml
authenticators:
  - name: internal-jwt
    jwt:
      issuer: https://sso.example.com
      jwks:
        uri: https://sso.example.com/jwks
      audiences: [observability-ingestion]
    attributes:
      tenant_id: {claim_path: [organization, id]}
      requested_tenant: {header: X-Tenant}
```

JWKS clusters use IPv4-only DNS resolution by default. For IPv6-only egress,
set `dns_lookup_family: V6_ONLY` under `jwks`. Other supported values are
`AUTO`, `V4_PREFERRED`, and `ALL`.

`claim_path` follows literal object keys in the token payload. Here,
`tenant_id` comes from `organization.id`, while `requested_tenant` uses the
original `X-Tenant` request header. Envoy keeps claims from different
authenticators separate. A missing or empty `X-Tenant` leaves
`requested_tenant` unset. Select the authenticator on a server as shown below.

## Authorization

A grant ties a named JWT authenticator to an API and allowed original
attribute values. For example, this server requires a valid token from
`internal-jwt`, the listed tenant claim, and the listed request header:

```yaml
authorization_policies:
  - name: metrics-writers
    grants:
      - authenticator: internal-jwt
        apis: [metrics-write]
        attributes:
          tenant_id: [client-123]
          requested_tenant: [client-123]

servers:
  - hostname: write.example.com
    authentication:
      any_of: [internal-jwt]
    authorization:
      any_of: [metrics-writers]
    apis: [metrics-write]
```

Define `metrics-write` under `apis` as in the [full example](../../config.example.yaml).
The client sends both the bearer token and header:

```http
POST /metrics/api/v1/receive HTTP/1.1
Host: write.example.com
Authorization: Bearer <token>
X-Tenant: client-123
```

Every attribute listed in the grant must match; a missing or unlisted value
is denied. The header is caller-supplied, and the grant checks its original
value alongside the verified claim. A route can use `requested_tenant` in
`processing.request_headers`, and an API can use it in `metrics.labels`.
Top-level `processing` mappings change those outputs without changing the
grant. The original `X-Tenant` header also reaches the backend unless it is
a managed output header. Changing the issuer, JWKS settings, attribute
sources, or grants requires regenerating the configuration and rolling out
the Deployment.
