# JWT

## Authentication

Envoy reads `Authorization: Bearer <token>` and verifies its signature
against the configured HTTPS JSON Web Key Set (JWKS). It checks `iss`,
requires a valid `exp`, and enforces `nbf` when present. Set `audiences`
to require a matching `aud` value; omit it to skip that check. Define
one named authenticator per issuer and map the verified claims needed
by grants or request processing:

```yaml
authenticators:
  - name: internal-jwt
    jwt:
      issuer: https://sso.example.com
      jwks:
        uri: https://sso.example.com/jwks
      audiences: [observability-ingestion]
      attributes:
        tenant_id:
          claim_path: [organization, id]
```

`claim_path` follows literal object keys in the token payload. Here,
`tenant_id` comes from `organization.id`. Envoy keeps claims from different
authenticators separate. Select the authenticator on a server as shown below.

## Authorization

A grant ties a named JWT authenticator to an API and an allowlist of
original claim values. For example, this server accepts tokens from
`internal-jwt` and forwards requests for `metrics-write` only when the
verified `tenant_id` is allowed:

```yaml
authorization_policies:
  - name: metrics-writers
    grants:
      - authenticator: internal-jwt
        apis: [metrics-write]
        attributes:
          tenant_id: [client-123, client-456]

servers:
  - hostname: write.example.com
    authentication:
      any_of: [internal-jwt]
    authorization:
      any_of: [metrics-writers]
    apis: [metrics-write]
```

Define `metrics-write` under `apis` as in the
[full example](../../config.auth.example.yaml). Every attribute listed in a
grant must match; a missing or unlisted value is denied. Authorization
uses the original verified claims, even when `processing` later maps them
to values sent upstream. Changing the issuer, JWKS settings, claim paths,
or grants requires regenerating the configuration and rolling out the
Deployment.
