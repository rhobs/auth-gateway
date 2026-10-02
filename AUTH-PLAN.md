# Authentication design and implementation plan

Proposal for [RHOBS-1784](https://redhat.atlassian.net/browse/RHOBS-1784), part of
[RHOBS-1782](https://redhat.atlassian.net/browse/RHOBS-1782).

The first implementation adds JWT authentication, identity mapping, server-bound
authorization policies with per-API grants, and optional upstream headers. Other
authentication methods and external processors will use the same stages.

See [config.auth.example.yaml](config.auth.example.yaml) for the complete proposed
JWT configuration and [config.mtls.example.yaml](config.mtls.example.yaml) for a
complete future mTLS example. Neither file's auth fields are implemented in the
current loader.
[config.example.yaml](config.example.yaml) describes the current supported format.

## Design

Authentication produces verified identity attributes. Authorization and request
processing consume those attributes independently.

```text
Server -> Authentication -> Identity mapping -> Authorization for the requested API -> Route processing -> Upstream
```

| Configuration | Responsibility |
| --- | --- |
| `authenticators` | Define named credential validators. Each JWT authenticator defines one issuer and its mappings. |
| `servers[].authentication` | Bind authenticators to a server using `any_of` or `all_of`. |
| Authenticator `attributes` | Extract verified credential values into named attributes, with optional value translation. |
| `authorization_policies` | Define named grants for APIs against verified identities. |
| `servers[].authorization` | Bind authorization policies to a server using `any_of` or `all_of`. |
| `routes[].processing` | Configure optional processing, starting with upstream request headers. |

TLS checks happen before this HTTP pipeline. Where a server enables mTLS, those
checks always require a valid client certificate. Within authentication, each
method must verify its credential and map its attributes before it can succeed.

Keep identity in internal request metadata, including each selected
authenticator, its credential provenance, and mapped attributes. JWT provenance
includes the issuer. Headers are an output of this process. They are never the
source of trusted identity.

Future client-certificate and API-key authenticators can produce the same
identity attributes. An `ext_authz` integration can consume them during
authorization, and `ext_proc` can consume them during request processing. Use
defined stages; an arbitrary ordered pipeline is outside this first step.

## Configuration behavior

### Server authentication

- Each authenticator defines one credential type. Each JWT authenticator has
  one issuer value, JWKS endpoint, audience list, and set of attribute mappings.
- A server explicitly selects `any_of` or `all_of` over authenticator names.
  With one authenticator, both have the same result.
- `any_of` uses declaration order. Select the first method that verifies its
  credential and maps its attributes successfully. Missing or invalid credentials
  and failed mappings let the next method try. Only the selected identity
  proceeds to authorization; an authorization denial never retries another
  method. Do not merge attributes from unselected methods.
- `all_of` requires every method to verify and map its credential. Reject
  conflicting values for shared attributes and combine nonconflicting values,
  while preserving each credential's provenance.
- More than one JWT authenticator in `all_of` is a configuration error: this
  version accepts only one bearer token. Use `any_of` for alternative issuers.
- An omitted `authentication` block permits public access. A present block must
  select exactly one combination with a nonempty list of distinct, known names.
  Nested combinations are outside this version.
- Authentication applies to the whole server. HTTP uses the selected hostname;
  HTTPS also requires matching SNI. An issuer bound only to another server must
  not authenticate a request here.
- Accept JWTs from `Authorization: Bearer`. Validate signatures, issuer,
  audience, expiration, and any not-before constraint. Require expiration and
  an explicit audience list. Remove the bearer credential before forwarding.
  Query parameters and cookies are not token sources in this first version.

Selection order is a gateway contract. Envoy's native JWT `any_of` can complete
asynchronously and does not guarantee that the first configured verifier wins.
Enforce selection independently of verifier completion timing. A single bearer
token from one of two distinct issuers can match only its issuer.

### Future mTLS

An mTLS authenticator defines a `client_ca_secret` and certificate attribute
mappings. The Secret contains the trusted client CA bundle in `ca.crt`; it is
separate from the server TLS Secret containing `tls.crt` and `tls.key`.

Any server that binds this authenticator must have `tls_config` and require a
valid, trusted client certificate at the TLS handshake. Missing, expired, or
untrusted client certificates fail the handshake, even if a valid JWT is
supplied and authentication uses `any_of`. Client TLS must reach Envoy directly
or through TLS passthrough.

With `any_of: [internal-jwt, writers-mtls]`, the certificate is mandatory, but
a successfully verified and mapped JWT supplies the identity first. Only if
that method fails does the gateway try the certificate's attribute mapping.
The certificate's attributes need not agree with a selected JWT identity.
With `all_of`, both mapped identities are required and shared attributes must
agree.

For the future example, `certificate_field: uri_san` selects exactly one URI
SAN from the validated peer certificate. Zero or multiple URI SANs make this
mapping unusable. The same nonempty string and value-translation rules apply
as for JWT attributes. These mTLS fields describe future behavior; the initial
runtime work remains JWT-only.

### Identity mapping

- Attribute names are configurable; `tenant_id` is an example, not a reserved
  requirement. An issuer can produce several attributes.
- `claim_path` is a nonempty list of literal object keys. `[x, y, z, claim]`
  selects `x.y.z.claim`; `[x, "y.z", claim]` selects a key containing a dot.
  Array traversal and JSONPath expressions are outside this first version.
- Each configured path must resolve to a nonempty string in the verified
  payload. Missing paths, nulls, numbers, booleans, arrays, and objects are
  rejected. Do not coerce values into strings.
- Without `mappings`, use the extracted string. When `mappings` is present,
  require an exact lookup match and use its nonempty string value. An unknown
  value is rejected rather than passed through. Translation happens once.
- Keep lookup tables per authenticator. Equal attribute values from different
  authenticators do not grant equal permissions unless the server's policies
  explicitly allow them.

### Server authorization

The server's `authorization` block references named policies using exactly one
of `any_of` or `all_of`, with a nonempty list of distinct, known names:

- `any_of` allows the request if any referenced policy grants access to the
  requested API.
- `all_of` allows the request only if every referenced policy grants access to
  that same API. Combining a metrics-only policy and a logs-only policy this way
  grants no access.

Policies contain allow grants; a policy with no matching grant does not allow
access. Policy order has no effect, and nested combinations are outside this
version.

Each grant identifies an `authenticator`, a nonempty `apis` list, and one or
more attribute allowlists. The authenticator name identifies the JWT issuer,
so grants have no separate `issuer` qualifier. The requested API must be in
the grant's list, and every attribute condition must match. Values within an
allowlist are alternatives; any matching grant makes that policy allow access.

Each grant evaluates the named credential's mapped attributes. Under
authentication `any_of`, only the selected credential can satisfy a grant.
Under `all_of`, each successful credential can satisfy its own grants. Policies
never evaluate unverified claims or request headers.

APIs contain upstreams, routes, and optional processing. Authorization bindings
belong to servers, and grants apply to every route in the named API. Different
servers can expose the same APIs with different authentication and permissions.
Use separate APIs when route permissions differ; there are no route policy
overrides. A grant cannot expose an API absent from the server's `apis` list.

| Server | Server authorization | Result |
| --- | --- | --- |
| Public | Omitted | Public access. |
| Authenticated | Policy list | Authenticate, map identity, then apply the policy combination for the requested API. |
| Authenticated | Omitted or combination does not allow access | Deny API access. |
| Public | Present | Reject the configuration. |

Unknown policy, authenticator, or API references are configuration errors.
Unsatisfied JWT credential requirements receive 401. Verified credentials that
cannot produce a required mapped identity, conflicting `all_of` attributes,
and identities denied by authorization receive 403. An unsuccessful `any_of`
method does not reject the request if a later method succeeds. Local 404/405
responses remain local responses after successful authentication on a protected
server. mTLS handshake failures happen before any HTTP response.

### Route processing

`processing.request_headers` maps attribute names to arbitrary application
headers using `name` and `from_attribute`. Omit processing when a route needs no
header output. The server's authorization rules still apply. Under `any_of`,
processing reads the selected identity; under `all_of`, it reads the combined
attributes.

Treat configured identity-header names as gateway-managed names. Remove
caller-supplied values before authentication and processing, then set one value
only on routes that declare the output. Reject missing source attributes and
unsafe header values. Validate header names and prevent identity output from
changing credential, routing, connection, or message-framing headers.

Keep the selected route stable through authorization and processing. Header
output must not cause a second route selection with different permissions.

## Complete examples

### JWT

The JWT example defines two authenticators, `internal-jwt` and `external-jwt`,
two authorization policies, and HTTP and HTTPS servers that expose the same
metrics and logs APIs. Each server uses `authentication.any_of` for the two
issuers and `authorization.any_of` for `metrics-writers` and `logs-writers`.
It uses placeholder issuer URLs, backend Services, and a pre-existing Kubernetes
TLS Secret. Gateway generation does not create those dependencies.

Both issuers map different external values into a shared tenant namespace:

| Authenticator | Extracted claim value | Mapped `tenant_id` | Metrics | Logs |
| --- | --- | --- | --- | --- |
| `internal-jwt` | `client-123` | `team-a` | Allow | Allow |
| `internal-jwt` | `client-456` | `team-b` | Allow | Deny |
| `external-jwt` | `customer-456` | `team-a` | Allow | Allow |
| `external-jwt` | `customer-789` | `team-b` | Deny | Allow |

Internal tokens use `[x, y, z, claim]`; external tokens use `[organization, id]`.
Both also extract a nonempty `sub` into `writer_id` without translation. The
metrics route sends `tenant_id` as `X-Scope-OrgID` and `writer_id` as
`X-Writer-ID`. The logs route sends only `X-Scope-OrgID`.

The HTTP server is suitable for the internal hop after an ingress terminates
TLS. The HTTPS server terminates TLS at the gateway using `write-gateway-tls`.
Both accept either JWT issuer and apply the permission table above.

### Future mTLS and combined methods

The mTLS example is a separate complete configuration with three HTTPS servers,
the same metrics and logs APIs, an `internal-jwt` authenticator, and a
`writers-mtls` authenticator. Each server has its own server TLS Secret and
requires a client certificate trusted by `writers-client-ca`.

Both methods map external values into `tenant_id`. JWT uses the same nested
claim as the JWT example; mTLS maps `urn:example:writer:client-123` to `team-a`
and `urn:example:writer:client-456` to `team-b`. Their other attributes,
`jwt_subject` and `certificate_id`, have distinct names and can combine under
`all_of`. The shared routes emit only `tenant_id` as `X-Scope-OrgID`.

| Server | Authentication | Authorization | Allowed APIs |
| --- | --- | --- | --- |
| `mtls.auth.example.com` | Certificate identity | `certificate-writers` | Metrics for either tenant; logs denied. |
| `jwt-preferred.auth.example.com` | JWT first, then certificate identity | Any of `jwt-writers`, `certificate-writers` | Metrics for either tenant; logs only for a selected JWT mapped to `team-a`. |
| `jwt-and-mtls.auth.example.com` | Both identities, with matching `tenant_id` | All of `jwt-writers`, `certificate-writers` | Metrics for either tenant; logs denied because the certificate policy does not allow them. |

A JWT for `team-a` with a valid certificate mapped to `team-b` selects the JWT
on the JWT-first server but fails identity agreement on the combined server.
All three servers reject a missing or invalid client certificate at the TLS
handshake, regardless of JWT validity.

## Implementation stages

1. Add the public configuration types, defaults, and validation. Cover named
   references, server authentication and authorization combinations, invalid
   two-JWT `all_of`, claim paths, mappings, API grants, and route processing
   before generating filters. Keep strict YAML decoding and avoid mutating
   caller-owned configuration.
2. Generate issuer-specific JWKS clusters and native Envoy JWT requirements.
   Use verified HTTPS for JWKS, scoped server requirements, and separate verified
   payload metadata for each issuer. HTTP servers share a connection manager,
   so issuer trust must be selected per virtual host.
3. Add an identity-mapping and selection stage that reads verified payload
   metadata and enforces configured order. Pass mapping settings as structured
   data. Publish trusted identity only after the required extraction,
   translation, and selection succeed. Mapping errors, including script errors,
   must never publish a usable identity for the failed method.
4. Generate native RBAC policies from each server's policy combination and API
   grants, plus a separate header-processing stage. Enforce the server's rules
   on every generated method route. Cover default denial, header sanitization,
   routes without header output, and reuse of APIs across servers with different
   permissions.
5. Add isolated e2e use cases, review the generated output, and update supported
   examples and operator documentation. Record checks in the handover and
   commit each tested implementation step on a feature branch.

Re-read RHOBS-1784 before runtime implementation. Keep RHOBS-1783 open until its
authentication-policy API requirement is resolved and tested. Mixed auth types
and external processors follow in later work.

## Testing

Start with focused unit tests and goldens, then exercise the generated gateway:

- Configuration and generation: invalid references and bindings, literal nested
  keys, mapping and grant validation, invalid two-JWT `all_of`, deterministic
  output, unchanged inputs, filter order, issuer isolation, server policy
  scoping, and Kubernetes configuration projection.
- Selection contract: the first verified and mapped method wins regardless of
  verifier completion timing; verification or mapping failure permits the next
  method; unselected identities cannot supply attributes or grants; and an
  authorization denial never retries another identity.
- JWT access: real signed tokens from two local issuers over HTTP and HTTPS;
  missing, malformed, expired, wrongly signed, wrong-audience, and wrong-issuer
  tokens; missing expiration; server and SNI/authority isolation.
- Identity and authorization: nested extraction, literal dots, direct values,
  translation, missing or wrong-type claims, unknown mappings, per-authenticator
  API grants, and denial without a grant. Cover authorization `any_of` and
  `all_of`, including disjoint API policies, and different grants for the same
  API on different servers. Verify rejected requests never reach the upstream.
- Processing: distinct headers per route, an authenticated route without header
  output, spoofed and duplicate managed headers, invalid header values, and
  removal of bearer credentials.
- JWKS lifecycle: key rotation without a gateway Pod restart; unavailable or
  invalid JWKS with cold and warm caches; cache lifetime and refresh behavior;
  and continued access through a healthy issuer when another issuer fails.
- Future mTLS: reject an HTTP binding; reject missing, expired, or untrusted
  certificates during TLS under both operators, including with a valid JWT;
  exercise single URI SAN extraction and mapping failures. Cover ordered JWT
  and certificate selection, `all_of` agreement and conflicts, combined
  nonconflicting attributes, and per-credential authorization provenance.
  Confirm mTLS on one server does not require client certificates on other
  servers. Add these runtime cases with the mTLS implementation.

Use local signing keys and controllable JWKS endpoints, with no dependency on
production SSO. Group JWT access and JWKS lifecycle scenarios into separate
Ginkgo `Ordered` containers, each with its own namespace, setup, cleanup, and
label. Keep Kubernetes lifecycle and diagnostics in `e2e/internal/framework`;
keep token helpers and protocol assertions in the e2e package. Test each
distinct behavior at the layer that owns it.

For runtime implementation, run `make test`, `go vet ./...`, e2e compilation and
vet checks, and `make -C e2e test` with the default two processes. Review updated
goldens and run `git diff --check`. For this documentation step, check both
example files for YAML syntax, duplicate keys, configuration references,
attribute sources, and agreement with this document's permissions. Check local
links, ASCII content, and whitespace.
