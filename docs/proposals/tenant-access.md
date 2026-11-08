# Tenant access configuration proposal

The [complete YAML example](tenant-access.example.yaml) contains both
access styles implemented by the current loader. JWT and API-key access use API-level authentication;
mTLS is a special server mode requiring client certificates for its entire API
set.

The `metrics-write` example combines:

- A concrete external JWT policy for `client-123`, using literal allowlists.
- A shared internal JWT policy for `client-456` and `client-789`, using a header
  value list and a comparison with the verified tenant attribute.
- A separate API-key policy for `customer-456`.

A dedicated `mtls-write.example.com` server exposes the same write API with
mandatory client-certificate authentication and no additional auth methods.

Header lists and attribute comparisons are optional. Concrete tenant entries
and literal attribute allowlists remain valid without them. There is no
separate tenancy block.

## Configuration ownership

- `authenticators` define credential validation and original attribute sources.
- `apis` define resources, methods, paths, upstreams, and forwarding.
- `servers[].apis[]` bind a resource to a hostname and its access rules.
- `servers[].tls_config.mtls` selects mandatory certificate authentication for
  every API bound to that server, replacing API-level authentication there.
- `access[].match` selects one access entry using original request headers.
- `access[].authentication` selects one credential type and its validators.
- `access[].authorization` grants access using that verified identity.

A grant already belongs to a server and API, so it does not repeat resource
names. Permission means access to that API's configured routes. `reader`,
`writer`, `admin`, and `viewer` are allowed raw attribute values, not built-in
gateway roles. In particular, `admin` does not implicitly grant write access.

## Access matrix

| Hostname | Resource | Requested tenant | Authentication | Authorization |
|----------|----------|------------------|----------------|---------------|
| `metrics.example.com` | `metrics-write` | `client-123` | External JWT | Credential tenant `organization-789`, role `writer`. |
| `metrics.example.com` | `metrics-write` | `client-456` or `client-789` | Internal JWT | Credential tenant equals requested tenant, role `writer`. |
| `metrics.example.com` | `metrics-write` | `customer-456` | Partner API key | Tenant equality, role `writer`, writer `agent-17` or `agent-18`. |
| `metrics.example.com` | `metrics-query` | `client-123` or `customer-456` | Internal or external JWT | Tenant equality; internal role `reader` or `admin`, external role `viewer`. |
| `internal-query.example.com` | `metrics-query` | `client-123` | Internal JWT | Tenant equality, role `reader` or `admin`. |
| `mtls-write.example.com` | `metrics-write` | `customer-456` | Mandatory client certificate | Verified URI SAN `spiffe://partners.example.com/customer-456` and DNS SAN `writer-17.partners.example.com`. |

Every access entry also requires `X-Environment: production`. This selects
requested context; it does not prove that the client is running in production.
The credential must independently grant access to the selected tenant and API.

## Matching and authorization

`tenant` labels a concrete access entry; `name` labels a shared entry. Matching
still determines the requested context. Each header matcher sets either
`exact` for one value or `in` for a nonempty list of exact allowed values. All
configured headers must match, and each request supplies one value per header.

Tenant selectors of different entries on the same server/API must not overlap,
even when other header conditions differ. A tenant therefore cannot choose a
different authentication method by changing an environment or client-type
header. Matching selects exactly one entry; failures do not try another entry.

Grant conditions must all succeed. An attribute condition has two forms:

- `role: [reader, admin]` checks the credential-derived value against a literal
  allowlist. A list-valued JWT claim can satisfy it with an allowed member.
- `tenant_id: {equals_attribute: requested_tenant}` compares the original
  values of two attributes declared by the same authenticator.

The shared internal writer rule uses:

```yaml
match:
  headers:
    X-Tenant: {in: [client-456, client-789]}
    X-Environment: {exact: production}
authentication:
  jwt:
    providers: [internal-jwt]
authorization:
  grants:
    - authenticator: internal-jwt
      attributes:
        tenant_id:
          equals_attribute: requested_tenant
        role: [writer]
```

For a comparison, the left-hand attribute must be credential-derived. The
referenced attribute may come from a matched request header, captured before
mutation. Both values must be nonempty scalar strings and exactly equal.
Missing, empty, or list-valued operands fail authorization. No normalization,
translation, or value merging occurs.

Allowing `client-456` and `client-789` in the header list does not let a token
for one request the other. The explicit comparison binds the particular header
value to the particular credential value. Independent header and credential
allowlists would not establish that equality.

The concrete external writer deliberately uses a different rule: a fixed grant
allows credential tenant `organization-789` to write to requested backend
tenant `client-123`. It does not configure equality. This illustrates that
literal grants and optional comparisons can coexist in the same API binding.

## Mandatory mTLS for dedicated write servers

Support mTLS only on dedicated HTTPS write servers. Do not support optional
client certificates followed by per-API certificate enforcement, or JWT/API-key
APIs sharing that server. This keeps certificate requirements at the TLS
handshake and removes shared-host authentication combinations from the model.

The new server selects `partner-cert` through `tls_config.mtls.authenticator`.
That shared authenticator declares an explicit client CA and certificate
attribute sources. The server also requires its own HTTPS certificate.

Selecting this mode always requires a trusted client certificate during the
TLS handshake. There is no optional-certificate setting. Missing, invalid, or
untrusted certificates fail before HTTP processing; JWTs and API keys cannot
replace the certificate. The example binds only `metrics-write` to this server.

Every API and tenant entry on that server inherits the same certificate
identity. Access entries contain matching and authorization, without an
`authentication` block. A trusted certificate still needs the configured tenant
and writer grants; trust in the CA alone does not grant this example's access.
SAN attributes retain their original values.

Reject the following as user configuration errors before generating resources:

- Any API-level `access[].authentication` anywhere in the mTLS server's bound
  API set, including another tenant, another API, or a redundant mTLS selection.
- Any grant naming an authenticator other than the server's selected mTLS
  authenticator, including JWT and API-key authenticators.
- A `tls_config.mtls` reference to a non-mTLS authenticator, or a missing client
  CA or server certificate configuration.

This restriction applies to that server's bindings. Other servers may expose
the same API using JWTs or API keys, and those authenticator definitions may
coexist in the gateway configuration. If a request includes JWT or API-key
headers alongside a valid certificate, those headers are ignored and removed;
only the certificate identity can authorize it.

## Request contract

On an mTLS server, mandatory certificate validation happens during TLS
establishment, before these HTTP request steps.

1. Match the hostname, API path, and HTTP method.
2. Select exactly one access entry using the original request headers.
3. Use the entry's JWT/API-key validator or inherit the server's verified client
   certificate identity.
4. Retain the verifying authenticator and its attributes as one identity.
5. Evaluate only grants for that authenticator in the selected entry.
6. Forward after a grant succeeds and required forwarding attributes exist.

Missing or empty access or grant configuration is a configuration error.
JWT/API-key entries require authentication configuration; mTLS entries must
omit it and inherit the server setting. Omission does not make an API public.
Public APIs use explicit `public: true` bindings and omit access entries.
Route-specific permission configuration is outside this design.

A JWT entry accepts one bearer token from `Authorization`. It lists one or more
named JWT authenticators with distinct issuers. The issuer can identify a
candidate verifier, but no claim is trusted until signature, issuer, audience,
and time checks pass. Providers are limited to the selected access entry.

An API-key entry selects one named API-key authenticator and its configured
header. Credentials of other types are ignored and removed before forwarding;
they cannot change the selected method or supply attributes. Supplying only
the wrong credential type fails authentication.

Every grant must name an authenticator enabled by its entry. At least one grant
for the verified authenticator must succeed. Literal grant conditions check
credential-derived attributes. A header alone never proves an identity or
tenant membership; it may be compared with a verified attribute as described
above.

Authentication failure returns `401`. A verified identity without a matching
grant returns `403`. An unknown tenant or missing selector returns `403`.
Repeated selector headers, comma-separated selector values, or repeated
selected credential headers return `400`. Unknown hosts and paths return
`404`; an unsupported method on a known path returns `405`.
An mTLS handshake failure has no HTTP authentication response.

## Attribute flow and backend isolation

Every authenticator declares `requested_tenant` from the original `X-Tenant`
header. It remains caller-supplied request context. A concrete selector and
literal grant authorize a fixed relationship; a grouped selector and comparison
require equality with the verified tenant attribute.

Routes replace any caller-supplied `X-Scope-OrgID` with that unchanged
`requested_tenant` value after authorization succeeds. Credential attributes
keep their original values. For the concrete external writer,
`organization-789` remains the credential tenant and `client-123` is forwarded
as the requested backend tenant.

The grouped query policy applies its provider-specific grants to both listed
tenants. Each provider's `tenant_id` must equal the requested backend tenant.
An external token asserting `tenant.id: organization-789` therefore cannot query
`client-123` under this policy; an external viewer must assert
`tenant.id: client-123`. The concrete write grant does not imply query access.

Bearer tokens, API keys, and internal identity headers are removed before
forwarding, including credential headers belonging to an unselected method.
The illustrative backend Services must enforce isolation using `X-Scope-OrgID`
and receive tenant-scoped traffic through the gateway.

API/status counters have no attribute labels in this example. Access
diagnostics should distinguish resource, requested tenant, verifying
authenticator, and authentication versus authorization failure without logging
credentials. Tenant context is request-scoped, including on reused HTTP
connections.

## Example identities

These are illustrative payloads, not signed tokens. Successful requests assume
valid signatures and current token lifetimes.

Internal writer for the shared `metrics-write` entry:

```json
{
  "iss": "https://sso.internal.example.com/realms/observability",
  "aud": "metrics-gateway",
  "sub": "alice",
  "organization": {"id": "client-456"},
  "role": "writer"
}
```

External writer for the concrete `metrics-write` entry:

```json
{
  "iss": "https://sso.customer.example.com/realms/customer",
  "aud": "metrics-gateway",
  "sub": "bob",
  "tenant": {"id": "organization-789"},
  "application_role": "writer"
}
```

An internal query reader instead asserts `organization.id: client-123` or
`customer-456`, with `role: reader`. An external query viewer asserts
`tenant.id: client-123` or `customer-456`, with `application_role: viewer`.

The API-key credential document format remains unchanged. This deliberately
fake key supplies the partner identity:

```yaml
credentials:
  - key: EXAMPLE-ONLY-NOT-A-REAL-KEY
    attributes:
      tenant_id: customer-456
      role: writer
      writer_id: agent-17
```

The mTLS writer certificate is signed by `partner-client-ca` and contains URI
SAN `spiffe://partners.example.com/customer-456` and DNS SAN
`writer-17.partners.example.com`. These produce the declared `tenant_id` and
`writer_id`; `requested_tenant` still comes from the request's `X-Tenant` header.

## Expected outcomes

Unless stated otherwise, requests use `metrics.example.com`, supply the named
tenant through `X-Tenant`, include `X-Environment: production`, and use
otherwise valid credentials.

| Request | Identity or change | Expected result |
|---------|--------------------|-----------------|
| Write `client-123` | External writer shown above. | Allowed; backend tenant is `client-123`. |
| Write `client-123` | External token has only role `viewer` or `admin`. | `403`. |
| Write `client-123` | External writer belongs to another credential tenant. | `403`. |
| Write `client-123` | Internal JWT or API key only. | `401`; only external JWTs are selected. |
| Write `client-456` | Internal writer shown above. | Allowed; backend tenant is `client-456`. |
| Write `client-789` | Internal writer asserts tenant `client-789`. | Allowed through the same shared entry. |
| Write `client-789` | Internal writer asserts tenant `client-456`. | `403`; header and credential tenants differ, even though both are listed. |
| Write `client-456` | Internal writer asserts tenant `client-789`. | `403`; header and credential tenants differ. |
| Write `client-456` | Internal token has only role `reader` or `admin`. | `403`; the grant requires `writer`. |
| Write `client-456` | Verified tenant attribute is missing, empty, or a list. | `403`; scalar equality fails. |
| Write `client-456` | External JWT or API key only. | `401`; only internal JWTs are selected. |
| Write `customer-456` | Partner key shown above. | Allowed; backend tenant is `customer-456`. |
| Write `customer-456` | Partner key has writer `agent-99` or another tenant. | `403`. |
| Write `customer-456` | Internal JWT only. | `401`; only API-key authentication is selected. |
| Write `customer-456` | Valid partner key plus an invalid JWT. | Allowed; only the key is evaluated. Neither credential is forwarded. |
| Query `client-123` or `customer-456` | Internal reader or external viewer asserting the same tenant. | Allowed through the shared query entry. |
| Query `client-123` | External viewer asserts tenant `organization-789`. | `403`; the query grant requires equality. |
| Query `client-123` | External token has only role `admin`. | `403`; the external grant requires `viewer`. |
| Query `client-123` | Internal reader asserts tenant `customer-456`. | `403`; the requested tenant must match. |
| Query `client-123` | Valid token from an unlisted issuer. | `401`. |
| Query `client-123` | Expired internal token plus a valid API key. | `401`; the key cannot rescue JWT authentication. |
| Query `customer-456` | Partner key only. | `401`; write access does not grant query access. |
| Any known API | Required environment header missing or different. | `403`; no access entry matches. |
| Any known API | Tenant missing or unknown. | `403`. |
| Any known API | Tenant header repeated or contains a comma-separated list. | `400`. |
| Query `client-123` on `internal-query.example.com` | External viewer for `client-123`. | `401`; this hostname selects only internal JWTs. |
| Query `customer-456` on `internal-query.example.com` | Valid internal reader. | `403`; this hostname has no matching tenant entry. |
| Write on `internal-query.example.com` | Any credential. | `404`; the write API is not exposed there. |
| Write `customer-456` on `mtls-write.example.com` | Trusted certificate with the configured URI and DNS SANs. | Allowed; backend tenant is `customer-456`. |
| Connect to `mtls-write.example.com` | No client certificate, including when a JWT or API key is available. | TLS handshake fails before HTTP processing. |
| Connect to `mtls-write.example.com` | Invalid or untrusted client certificate. | TLS handshake fails before HTTP processing. |
| Write on `mtls-write.example.com` | Trusted certificate with an unauthorized tenant or writer SAN. | `403`; the authorization grant fails. |
| Query on `mtls-write.example.com` | Valid client certificate. | `404`; no query API is bound. |
| Authorized query `client-123` | Caller supplies `X-Scope-OrgID: customer-456`. | Backend receives `X-Scope-OrgID: client-123`. |

Authentication and authorization denials must not reach the backend. Allowed
requests still depend on backend availability and return its status.

## Migration and operations

This completely replaces the current access model, with no backward
compatibility requirement. Migrate the schema, loader validation, Envoy
generation, configuration examples and reference, fixtures, goldens, and
unit/runtime/e2e tests together.

Remove general server-wide authentication and authorization selections, global
authorization policies, general `any_of`/`all_of` composition, mixed-method
fallback and precedence, and attribute merging and equality checks between
credentials. The explicit authorization comparison between a verified attribute
and request context remains part of the new model. Do not retain legacy
configuration acceptance or an adapter between models.

Keep shared credential validators, provider provenance, original source values,
credential reload behavior, and forwarding protections. Test selector
uniqueness, tenant/resource isolation, selected credential validation,
provider-specific grants, and header-to-credential comparisons. Cover mTLS
exclusivity configuration errors, mandatory certificate handshakes, and
certificate-based tenant authorization. mTLS is the explicit server-level
exception to API-level authentication.

The deployment requires the `observability` namespace, both backend Services,
reachable JWKS endpoints, a `metrics-gateway-tls` Secret covering both hostnames,
and the generated API-key resource from `metrics-api-keys`. No live credentials
or resources are supplied here.
The mTLS server also needs `mtls-write-gateway-tls` covering its hostname and a
`partner-client-ca` ConfigMap containing the trusted client CA in `ca.crt`.

Selectors, authentication, authorization, routes, and forwarding remain static
bootstrap configuration. Changes require regeneration and an explicit Envoy
Deployment rollout. Credential-only API-key updates retain the existing reload
mechanism. Switching a tenant/resource to another credential type is a
coordinated configuration change without a mixed-method migration window.
Client CA updates retain the existing reload behavior for new TLS connections.
