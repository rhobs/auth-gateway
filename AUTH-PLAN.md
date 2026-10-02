# Authentication design and implementation plan

Proposal for [RHOBS-1784](https://redhat.atlassian.net/browse/RHOBS-1784), part of
[RHOBS-1782](https://redhat.atlassian.net/browse/RHOBS-1782).

The first implementation adds JWT authentication, identity mapping, per-API
authorization, and optional upstream headers. Other authentication methods and
external processors will use the same stages.

See [config.auth.example.yaml](config.auth.example.yaml) for the complete proposed
configuration. Its auth fields are not implemented in the current loader.
[config.example.yaml](config.example.yaml) describes the current supported format.

## Design

Authentication produces verified identity attributes. Authorization and request
processing consume those attributes independently.

```text
Server -> Authentication -> Identity mapping -> API authorization -> Route processing -> Upstream
```

| Configuration | Responsibility |
| --- | --- |
| `authenticators` | Define named credential validators. Each JWT authenticator contains its trusted issuers and their mappings. |
| `servers[].authentication` | Bind authenticators to a server using `any_of` or `all_of`. |
| Issuer `attributes` | Extract verified claims into named attributes, with optional value translation. |
| `authorization_policies` | Define named grants against verified identities. |
| `apis[].authorization` | Apply one named policy to every route in the API. |
| `routes[].processing` | Configure optional processing, starting with upstream request headers. |

Keep identity in internal request metadata, including the authenticator, issuer,
and mapped attributes. Headers are an output of this process. They are never the
source of trusted identity.

Future client-certificate and API-key authenticators can produce the same
identity attributes. An `ext_authz` integration can consume them during
authorization, and `ext_proc` can consume them during request processing. Use
defined stages; an arbitrary ordered pipeline is outside this first step.

## Configuration behavior

### Server authentication

- A JWT authenticator accepts a token from any one of its configured issuers.
  Each issuer has its own issuer value, JWKS endpoint, audiences, and mappings.
- A server explicitly selects `any_of` or `all_of` over authenticator names.
  With one authenticator, both have the same result. For the initial JWT work,
  bind one JWT authenticator per server and list its issuers within it.
- Future `any_of` policies need one successful method. Future `all_of` policies
  need every method. Preserve each successful credential's provenance. Reject
  conflicting values for shared attributes and combine nonconflicting values.
- An omitted `authentication` block permits public access. A present block must
  select exactly one combination with a nonempty list of distinct, known names.
- Authentication applies to the whole server. HTTP uses the selected hostname;
  HTTPS also requires matching SNI. An issuer bound only to another server must
  not authenticate a request here.
- Accept JWTs from `Authorization: Bearer`. Validate signatures, issuer,
  audience, expiration, and any not-before constraint. Require expiration and
  an explicit audience list. Remove the bearer credential before forwarding.
  Query parameters and cookies are not token sources in this first version.

JWT issuers are always alternatives, including when the server uses `all_of`.
For future mTLS combinations, account for certificate checks during the TLS
handshake. HTTP policy composition cannot undo a failed handshake, and simply
chaining filters that each reject missing credentials does not implement OR.

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
- Keep lookup tables per issuer. Equal tenant values from different issuers do
  not grant equal permissions unless the API policy explicitly allows them.

### API authorization

An API references one named policy through `authorization`. All its routes
inherit that policy. Use separate APIs when permissions differ; this version
has no route policy overrides.

Each grant identifies an authenticator, one of its issuers, and one or more
attribute allowlists. All conditions within a grant must match. Values within
an allowlist are alternatives, and any matching grant permits access. Policies
evaluate mapped attributes, not the original claim values or request headers.

| Server | API policy | Result |
| --- | --- | --- |
| Public | Omitted | Public access. |
| Authenticated | Named policy | Authenticate, map identity, then evaluate grants. |
| Authenticated | Omitted or empty grants | Deny API access. |
| Public | Named policy | Reject the configuration. |

Unknown policy, authenticator, or issuer references are configuration errors.
A valid identity with no matching grant receives 403. Invalid or missing JWTs
receive 401; unusable mapped identities receive 403. Local 404/405 responses
remain local responses after successful authentication on a protected server.

### Route processing

`processing.request_headers` maps attribute names to arbitrary application
headers using `name` and `from_attribute`. Omit processing when a route needs no
header output. API authorization still applies.

Treat configured identity-header names as gateway-managed names. Remove
caller-supplied values before authentication and processing, then set one value
only on routes that declare the output. Reject missing source attributes and
unsafe header values. Validate header names and prevent identity output from
changing credential, routing, connection, or message-framing headers.

Keep the selected route stable through authorization and processing. Header
output must not cause a second route selection with different permissions.

## Complete example

The example defines two issuers, two API policies, and HTTP and HTTPS servers
that expose the same metrics and logs APIs. It uses placeholder issuer URLs,
backend Services, and a pre-existing Kubernetes TLS Secret. Replace those
references for a deployment; gateway generation does not create the issuers,
backends, or certificate.

Both issuers map different external values into a shared tenant namespace:

| Issuer | Extracted claim value | Mapped `tenant_id` | Metrics | Logs |
| --- | --- | --- | --- | --- |
| `internal` | `client-123` | `team-a` | Allow | Allow |
| `internal` | `client-456` | `team-b` | Allow | Deny |
| `external` | `customer-456` | `team-a` | Allow | Allow |
| `external` | `customer-789` | `team-b` | Deny | Allow |

Internal tokens use `[x, y, z, claim]`; external tokens use `[organization, id]`.
Both also extract a nonempty `sub` into `writer_id` without translation. The
metrics route sends `tenant_id` as `X-Scope-OrgID` and `writer_id` as
`X-Writer-ID`. The logs route sends only `X-Scope-OrgID`.

The HTTP server is suitable for the internal hop after an ingress terminates
TLS. The HTTPS server terminates TLS at the gateway using `write-gateway-tls`.
Both accept either JWT issuer. Their single-entry `any_of` and `all_of` bindings
have equivalent authentication behavior.

## Implementation stages

1. Add the public configuration types, defaults, and validation. Cover named
   references, server bindings, claim paths, mappings, policy grants, and route
   processing before generating filters. Keep strict YAML decoding and avoid
   mutating caller-owned configuration.
2. Generate issuer-specific JWKS clusters and native Envoy JWT requirements.
   Use verified HTTPS for JWKS, scoped server requirements, and separate verified
   payload metadata for each issuer. HTTP servers share a connection manager,
   so issuer trust must be selected per virtual host.
3. Add a small identity-mapping filter that reads verified payload metadata.
   Pass mapping settings as structured data. Publish trusted identity only
   after extraction and translation succeed. Mapping errors, including script
   errors, must prevent authorization.
4. Generate native RBAC policies from API grants and a separate header-processing
   stage. Enforce the same policy on every generated method route. Cover default
   denial, header sanitization, and routes without header output.
5. Add isolated e2e use cases, review the generated output, and update supported
   examples and operator documentation. Record checks in the handover and
   commit each tested implementation step on a feature branch.

Re-read RHOBS-1784 before runtime implementation. Keep RHOBS-1783 open until its
authentication-policy API requirement is resolved and tested. Mixed auth types
and external processors follow in later work.

## Testing

Start with focused unit tests and goldens, then exercise the generated gateway:

- Configuration and generation: invalid references and bindings, literal nested
  keys, mapping and grant validation, deterministic output, unchanged inputs,
  filter order, issuer isolation, and Kubernetes configuration projection.
- JWT access: real signed tokens from two local issuers over HTTP and HTTPS;
  missing, malformed, expired, wrongly signed, wrong-audience, and wrong-issuer
  tokens; missing expiration; server and SNI/authority isolation.
- Identity and authorization: nested extraction, literal dots, direct values,
  translation, missing or wrong-type claims, unknown mappings, per-issuer API
  grants, and denial without a grant. Verify rejected requests never reach the
  upstream.
- Processing: distinct headers per route, an authenticated route without header
  output, spoofed and duplicate managed headers, invalid header values, and
  removal of bearer credentials.
- JWKS lifecycle: key rotation without a gateway Pod restart; unavailable or
  invalid JWKS with cold and warm caches; cache lifetime and refresh behavior;
  and continued access through a healthy issuer when another issuer fails.

Use local signing keys and controllable JWKS endpoints, with no dependency on
production SSO. Group JWT access and JWKS lifecycle scenarios into separate
Ginkgo `Ordered` containers, each with its own namespace, setup, cleanup, and
label. Keep Kubernetes lifecycle and diagnostics in `e2e/internal/framework`;
keep token helpers and protocol assertions in the e2e package. Test each
distinct behavior at the layer that owns it.

For runtime implementation, run `make test`, `go vet ./...`, e2e compilation and
vet checks, and `make -C e2e test` with the default two processes. Review updated
goldens and run `git diff --check`. For this documentation step, check YAML
syntax, configuration references, and consistency with this document.
