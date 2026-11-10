# JWT

## Authentication

Envoy reads one `Authorization: Bearer <token>` header and verifies its
signature against the configured HTTPS JSON Web Key Set (JWKS). It checks
`iss`, requires a valid `exp`, and enforces `nbf` when present. Set `audiences`
to require a matching `aud`; omit it to skip that check.

Define a named authenticator and declare original attribute sources:

```yaml
authenticators:
  - name: internal-jwt
    jwt:
      issuer: https://sso.example.com
      jwks:
        uri: https://sso.example.com/jwks
      audiences: [observability-ingestion]
    attributes:
      - name: tenant_id
        from_source: claim
        value: [organization, id]
      - name: role
        from_source: claim
        value: [role]
      - name: upstream_tenant
        from_source: claim
        value: [organization, upstream_tenant]
      - name: requested_tenant
        from_source: header
        value: X-Tenant
```

Claim `value` follows literal object keys, including keys containing dots.
Headers retain their original values until authorization completes. JWKS
clusters default to IPv4-only DNS; `V6_ONLY`, `AUTO`, `V4_PREFERRED`, and `ALL`
are also supported in `jwks.dns_lookup_family`.

## Tenant access

This shared write entry accepts two requested tenants. Each token must prove
access to the particular tenant in its header and have the writer role:

```yaml
servers:
  - hostname: write.example.com
    apis:
      - name: metrics-write
        access:
          - name: internal-writers
            match:
              headers:
                - name: X-Tenant
                  expression: in
                  value: [client-123, client-456]
            authentication:
              jwt: {providers: [internal-jwt]}
            authorization:
              grants:
                - authenticator: internal-jwt
                  attributes:
                    - name: tenant_id
                      expression: equals-attribute
                      value: requested_tenant
                    - name: role
                      expression: equals
                      value: writer
```

Define `metrics-write` under `apis` as in the [full example](../../config.example.yaml).
A client sends its bearer token and requested tenant:

```http
POST /metrics/api/v1/receive HTTP/1.1
Host: write.example.com
Authorization: Bearer <token>
X-Tenant: client-123
```

When a JWT and an API key serve the same path and tenant, add
`{name: Authorization, expression: present}` to the JWT access entry's
`match.headers`. The key entry selects its configured key header with
`expression: present`, as in the [full example](../../config.example.yaml).

Equality requires nonempty scalar strings. A token for `client-123` cannot
select `client-456` even though both headers are listed. A concrete entry can
instead use `expression: equals` with `value: client-123` on `X-Tenant` and a
literal `tenant_id` grant with `value: organization-789` when that organization is explicitly permitted
to write for the requested tenant.

## Claim presence

Use `present` when a verified claim must contain a nonempty string but no
particular value is required:

```yaml
- name: writer_id
  expression: present
```

The attribute must be declared by the selected JWT authenticator. Missing,
empty, null, numeric, and list-valued claims do not match. Use `has` or
`has-one-of` when a list must contain a particular string.

## Group membership

Declare a verified list claim with the same nested key path syntax:

```yaml
- name: groups
  from_source: claim
  value: [token, groups]
```

For a JWT claim `{"token":{"groups":["metrics-readers","metrics-admins"]}}`,
these grant conditions each match:

```yaml
- name: groups
  expression: has
  value: metrics-admins

- name: groups
  expression: has-one-of
  value: [metrics-readers, metrics-writers]
```

Use them in separate grants because a grant cannot repeat an attribute name.
The claim must be a list. A scalar string, missing claim, null, or empty list
does not match. Matching is case-sensitive. Non-string list elements are
ignored; a matching string element still grants access. List claims are not
available as upstream header values, metric labels, or fault injection
selectors.

## Multiple providers

A JWT entry can set `providers: [internal-jwt, external-jwt]` to trust either
named provider. Define both under `authenticators` and give each its own
`authorization.grants` entry. Issuers must be distinct within an entry.
Provider-specific claims, tenant checks, and role values stay separate; one
provider's token cannot borrow another provider's grant. The selected API and
tenant determine which providers are trusted before token validation.

## Forwarding

Use `from_attribute: requested_tenant` to forward the authorized original
request tenant as `X-Scope-OrgID`. When an upstream needs another value,
declare another verified claim source. For example,
`{"organization":{"id":"client-123","upstream_tenant":"team-a"}}` supplies
the additional attribute declared above:

```yaml
request_headers:
  - name: X-Scope-OrgID
    from_attribute: upstream_tenant
```

The gateway sends the source value `team-a` unchanged, replacing any caller
value. Missing required output values cause a denial before the backend.
Changing issuers, JWKS settings, access, attribute sources, or output mappings
requires regeneration and an explicit Deployment rollout.
