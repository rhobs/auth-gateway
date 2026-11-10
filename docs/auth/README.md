# Authentication and authorization

The gateway supports [JWT](jwt.md), [API keys](api-key.md),
[client-certificate mTLS](mtls.md), and [external authorization](ext-authz.md).
Shared `authenticators` define credential
validation and original attribute sources. Access belongs to each
`servers[].apis[]` binding. See the [complete example](../../config.example.yaml)
and [configuration reference](../configuration-reference.md).

## Request selection

Each API binding requires protected `access` entries or explicit `public: true`.
An entry's `match.headers` selects the request context using `equals`, `in`, or
`present` expressions. All configured headers must match. `present` checks
whether the header exists and takes no `value`. `tenant` labels a
concrete entry; `name` labels a shared entry. Labels themselves do not match
requests.

Two entries may cover the same tenant and API path when the JWT entry requires
`Authorization: present` and the API-key entry requires the configured key
header with `present`. Each credential header can select only its own
authentication method. Other overlapping entries remain invalid. See the
[full example](../../config.example.yaml) for a shared write path. Missing or
unmatched context returns `403` before the backend. Repeated selectors,
repeated selected credential headers, and comma-separated selectors return
`400`.

## Authentication

A protected entry with local authentication selects exactly one method:

- `authentication.jwt.providers` names one or more trusted JWT authenticators.
- `authentication.api_key.authenticator` names the API-key authenticator.

Only the selected method authenticates that request. A valid key cannot
replace a missing or invalid JWT on a JWT entry. Another credential never
contributes missing attributes. Multiple JWT providers can serve the same
read API while keeping their verified claims separate. A gateway can define
multiple JWT and mTLS authenticators and one API-key authenticator.

When an API-key authenticator is configured, any request carrying both its
credential header and `Authorization` returns `403` before authentication and
the backend, regardless of the path or selected access method. A matched API
with request metrics configured still counts the `403` response.

An entry using `authorization.ext_authz` may omit `authentication`. Its service
then authenticates and authorizes the selected request.

mTLS uses a dedicated HTTPS server mode: `tls_config.mtls.authenticator` names
the certificate validator for every API on that server. Client certificates
are always required during TLS establishment. Access entries omit
`authentication`; additional API-level authentication is a configuration error.

## Authorization

Each entry selects local `authorization.grants` or `authorization.ext_authz`.
Local grants name their verifying authenticator and
credential attribute conditions. Any applicable grant can allow the request;
every condition within that grant must match. Roles are literal attribute
values, with no implicit inheritance.

`equals` compares a scalar attribute to one string, and `in` checks whether a
scalar attribute is in a configured list. For verified JWT list claims, `has`
checks one exact string element and `has-one-of` accepts any string from a
configured list. Optional `equals-attribute` on
`tenant_id` with `value: requested_tenant` binds the verified tenant to
an original request header declared by the same authenticator. Both values
must be nonempty scalar strings. A header used in equality must also appear
in `match.headers`. Listing two tenants never permits a credential for one to
impersonate the other.

Authorization failure returns `403`. Invalid selected credentials normally
return `401`; the pinned Envoy version returns `403` for an untrusted JWT
audience. Missing or invalid mTLS certificates fail the TLS handshake.
External denials use the service's status; Check errors and timeouts return
`503`.

## Forwarding

Route processing replaces caller-supplied managed headers with declared source
values after authorization. Forward the authorized request tenant with
`from_attribute: requested_tenant`, or declare a separate verified source when
an upstream needs another value. Required values must exist before a request
can reach the backend. Bearer tokens, configured API keys, and internal identity
headers are removed before forwarding. Header attributes declared by an
external authorization service can also supply managed headers.

Changes to access, validators, attribute sources, or forwarding require
regeneration and an explicit Deployment rollout. API-key sets and mTLS client
CA bundles have the update behavior described in their method guides.
