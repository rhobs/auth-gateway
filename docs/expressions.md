# Expressions and keywords

This reference lists the supported expressions and keyword choices at each
configuration layer. The [configuration reference](configuration-reference.md)
lists every field, default, and numeric constraint. Unknown fields and
unsupported expression names or keyword values are rejected.

## Table of contents

- [Expression availability](#expression-availability)
- [Servers and API bindings](#servers-and-api-bindings)
- [Routes](#routes)
- [Fixed API attributes](#fixed-api-attributes)
- [Request header selectors](#request-header-selectors)
- [Authenticators and attribute sources](#authenticators-and-attribute-sources)
- [Authorization grants](#authorization-grants)
- [External authorization](#external-authorization)
- [Forwarding, metrics, and fault selectors](#forwarding-metrics-and-fault-selectors)
- [Protocol and TLS choices](#protocol-and-tls-choices)

## Expression availability

Conditions use `expression` and exactly one operand: `value` for a literal or
`value_from: {attribute: name}` for a declared attribute. `present` and
`nonempty` take no operand. Named conditions also set `name`; route paths
have an implicit target and omit it.

| Layer | Expressions | Operand |
|-------|-------------|---------|
| Route path | `equals`, `prefix`, `regex` | Literal string. |
| Access header selectors | `equals`, `in`, `present` | String, distinct string list, or no operand, respectively. |
| Local grant attributes | `equals`, `in`, `nonempty`, `has`, `has-one-of` | String or attribute reference for `equals`; list for `in` and `has-one-of`; string for `has`; none for `nonempty`. |
| Fault header selectors | `equals` | Literal string. |
| Fault attribute selectors | `in` | Nonempty list of distinct strings. |

`equals` compares scalar strings. `in` checks scalar membership; `has` and
`has-one-of` check exact elements of verified JWT lists. `present` checks
header existence, including empty values. `nonempty` requires a nonempty
verified scalar string. Missing and incorrectly typed values fail closed.

Expression names and matched values are case-sensitive. Match strings must
be nonempty and contain no control characters or surrounding whitespace.
List items follow the same rules. Quote numeric-looking strings, such as
`"123"`, so YAML preserves their type.

## Servers and API bindings

`servers[].hostname` accepts one exact DNS hostname. Each entry under
`servers[].apis[]` names an existing API and selects its access mode:

| Keyword        | Meaning                                                       |
|----------------|---------------------------------------------------------------|
| `public: true` | Explicit public access. Omit `access`.                        |
| `access`       | Protected entries selecting authentication and authorization. |
| `tenant`       | Labels one access entry with a concrete tenant value.         |
| `name`         | Labels one shared access entry.                               |

Every protected entry sets exactly one of `tenant` or `name`. These are labels;
request matching uses `match.headers`. Public access cannot be combined with
server mTLS or authenticated header forwarding. See
[API bindings and access entries](concepts.md#api-bindings-and-access-entries).

## Routes

Under `apis[].routes[]`, `methods` accepts `CONNECT`, `DELETE`, `GET`, `HEAD`,
`OPTIONS`, `PATCH`, `POST`, `PUT`, and `TRACE`. Methods must be unique within
a route.

Set `path.expression` and its literal `path.value`:

| Keyword  | Meaning                                                      |
|----------|--------------------------------------------------------------|
| `equals` | Match one complete path.                                     |
| `prefix` | Match the beginning of a path. `/api` also matches `/apiv2`. |
| `regex`  | Match the complete path using an RE2 regular expression.     |

Exact and prefix matching are case-sensitive. Exact and regex matching exclude
the query string. Exact paths and prefixes must be clean absolute paths without
a query or fragment; a prefix may end in `/`.

An optional `rewrite` selects exactly one mode:

| Keyword  | Meaning                                                                                     |
|----------|---------------------------------------------------------------------------------------------|
| `path`   | Replace the path.                                                                           |
| `prefix` | Replace the matched prefix.                                                                 |
| `regex`  | Apply `pattern` and `substitution` to the path. An omitted substitution is an empty string. |

See [route fields](configuration-reference.md#routes-and-path-matching) for
path restrictions and
[Envoy regex matching and substitution](https://www.envoyproxy.io/docs/envoy/v1.39.1/api-v3/type/matcher/v3/regex.proto)
for regex syntax and capture references.

## Fixed API attributes

Location: `apis[].attributes[]`.

API attributes accept only `from: {fixed: value}`, with a nonempty string
value containing no control characters or surrounding whitespace. The value
is available on every matching method route, including public routes and all
server bindings of the API. Generated `404` and `405` fallback routes do not
have API attributes.

Fixed API attributes can supply upstream headers, metric labels, and external
authorization inputs. They cannot supply local grant conditions or reuse names declared by a selected authenticator or external
service. See [API attributes](configuration-reference.md#api-attributes).

## Request header selectors

Location: `servers[].apis[].access[].match.headers[]`.

Use `equals`, `in`, or `present` from the
[expression table](#expression-availability). Every configured header condition
must match. Header names are case-insensitive; values are case-sensitive.
Selector values cannot contain commas. Repeated selector headers and
comma-separated request values are rejected.

Credential headers support only `present`: `Authorization` requires JWT
authentication on that entry, and the configured API-key header requires
API-key authentication. Presence selects the method; credential validation
still applies.

An empty `match.headers` list is a catch-all and must be the binding's only
access entry. See [request selection](auth/README.md#request-selection) for
overlap rules and request outcomes.

## Authenticators and attribute sources

Each `authenticators[]` entry selects exactly one of `jwt`, `api_key`, or
`mtls`. Access entry `authentication` selects `jwt.providers` or
`api_key.authenticator`. Server mTLS selects
`tls_config.mtls.authenticator`; its access entries omit `authentication`.

Declare attributes under `authenticators[].attributes[]`:

| Key under `from` | Available on | Operand                                                              |
|---------------|--------------------|-------------------------------------------------------------------------------|
| `claim`       | JWT.               | Nonempty list of literal claim keys, such as `[organization, id]` or `[sub]`. |
| `credential`  | API keys.          | Attribute name from the API-key credential's `attributes` map.                |
| `certificate` | mTLS.              | Exactly `uri_san` or `dns_san`.                                               |
| `header`      | Any authenticator. | Original request header name.                                                 |
| `fixed` | Any authenticator. | Nonempty literal string without controls or surrounding whitespace. |

Claim paths select nested object keys. Attribute names such as `role`, `groups`,
and `tenant_id` are user-defined; their meaning comes from the source and grant
configuration. Values are used unchanged. Header sources cannot read credential
or reserved identity, routing, connection, or framing headers.

Fixed authenticator attributes become available only after that authenticator
verifies the request. They can supply upstream headers, metrics, and declared
external service inputs. Local grant conditions cannot use fixed sources.

See [authenticator fields](configuration-reference.md#authenticators) for name
and source restrictions, and [authentication](auth/README.md#authentication)
for provider selection.

## Authorization grants

Location: `servers[].apis[].access[].authorization.grants[]`.

Each grant names its verifying `authenticator` and a list of attribute
conditions under `match.attributes`. The grant expressions in the
[expression table](#expression-availability) are subject to their source types.
Every condition within a grant must match; any applicable grant can allow the
request. An attribute name can appear only once within a grant.

- `equals`, `in`, and `nonempty` use verified JWT claims, API-key attributes,
  or certificate SANs. Their source must be a scalar string.
- `has` and `has-one-of` require a verified JWT list claim. They compare exact
  string elements; non-string elements are ignored.
- `equals` with `value_from.attribute` compares two attributes declared by the
  same authenticator.
  Its left side must come from a verified credential. The right side can come
  from another verified attribute or a request header. That header must also
  appear in the access entry's `match.headers`.

Fixed API and authenticator attributes cannot be used on either side of a
local grant condition.

Missing or incorrectly typed values do not match. In particular, `in` does not
match a list-valued source, and `nonempty` does not match an empty
string, list, number, boolean, or null.

JWT and API-key grants require at least one condition. An mTLS grant can omit
`match.attributes` or use `[]` to allow any certificate trusted by that server's CA.
See [authorization](auth/README.md#authorization) for access outcomes and the
[JWT guide](auth/jwt.md) for condition examples.

## External authorization

Each protected entry selects exactly one of `authorization.grants` or
`authorization.ext_authz`. The latter names an `ext_authz_services[]` entry
through `service`. Local authentication may be omitted when the service
handles authentication itself.

External service attributes use a context-specific set of `from` keys under
`ext_authz_services[].attributes[]`:

| Key under `from` | Operand                             | Restrictions                                                                                                                      |
|-----------------|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `header`        | Original request header name.                | Must be a safe `request_headers` entry and cannot be a credential header or collide with a selected authenticator attribute name. |
| `attribute` | Declared local authenticator attribute name. | Must equal this attribute's `name` and be declared by every selected local authenticator.                                         |

`request_headers` lists headers sent to the service. `credential_headers` is a
subset removed before forwarding to the API backend. These attributes are
inputs to the check; the gateway rejects response header mutations. Only
nonempty scalar attribute strings are sent. An entry without local
authentication sends no authenticator attributes.

Every fixed attribute on the matched API is sent automatically in the same
metadata namespace. Do not repeat it under `ext_authz_services[].attributes`.
Fixed authenticator attributes use `from.attribute` and are sent
only after their authenticator verifies the request.

See [external authorization](auth/ext-authz.md) for the check contract.

## Forwarding, metrics, and fault selectors

Forwarding and metrics reference declared scalar attributes:

| Location                                       | Syntax and meaning                                                                                                  |
|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `apis[].routes[].processing.request_headers[]` | `name` sets the upstream header; `from.attribute` names its source attribute.                                       |
| `apis[].metrics.labels`                        | Map each label to `{from: {attribute: name}}`. `metrics: {}` enables API and status counts without extra labels. |

These fields do not accept `expression`. Fixed API attributes are available
for both public and protected bindings. Other attributes required by header
forwarding must be provided by every protected access entry. Missing required
values deny forwarding; missing or unsafe metric values become
`__unattributed__`. JWT lists are available for grant conditions only.

Fault injection is configured under `servers[].apis[].fault_injection`:

| Location | Supported conditions |
|----------|----------------------|
| `match.headers[]` | `name`, `expression: equals`, and a literal string `value`. |
| `match.attributes[]` | `name`, `expression: in`, and a literal string list `value`. |

All conditions must match; list values are alternatives. Attribute targets must
be declared by every selected local authenticator on every protected access
entry and come from verified claims, credentials, or certificate SANs. Public
bindings and external-only authentication cannot use fault attribute selectors.
Fixed and header sources cannot supply fault attributes. Missing, empty, or
incorrectly typed runtime values do not match.

Fault header selectors cannot use credential or reserved headers, or headers
overwritten by route processing. Omitting `match` selects all requests that
pass authorization and required-header checks. Each server binding can set
its own fault policy for the same API.

See [forwarding](auth/README.md#forwarding),
[API metrics](configuration-reference.md#api-metrics), and
[fault injection](fault-injection.md) for examples and behavior.

## Protocol and TLS choices

| Location                                      | Supported choices                                                                                   |
|-----------------------------------------------|-----------------------------------------------------------------------------------------------------|
| Top-level `version`                           | Integer `1`.                                                                                        |
| `apis[].upstream.http_protocol`               | `http1` or `http2`; defaults to `http1`. The `http2` options block requires `http_protocol: http2`. |
| `ext_authz_services[].upstream.http_protocol` | `http2`, with `tls_config` required.                                                                |
| `authenticators[].jwt.jwks.dns_lookup_family` | `AUTO`, `V4_ONLY`, `V6_ONLY`, `V4_PREFERRED`, or `ALL`; defaults to `V4_ONLY`.                      |
| `trusted_ca`                                  | Exactly one of `filename` or `config_map`. `config_map` requires Kubernetes output.                 |
| `servers[].tls_config`                        | Omit for HTTP; set for HTTPS. Its `mtls` block requires client certificates.                        |

Boolean switches use `true` or `false`. Duration fields use strings with units,
such as `250ms`, `5s`, or `1m`, and must be at least `1ms`. See
[trusted CA settings](configuration-reference.md#trusted-ca) and
[traffic protection](traffic-protection.md) for related configuration.
