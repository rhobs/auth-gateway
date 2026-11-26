# API expression and keyword alignment

Status: Implemented. The supported API is documented in
[expressions and keywords](../expressions.md).

## Table of contents

- [Purpose](#purpose)
- [Condition syntax](#condition-syntax)
- [Source declarations and references](#source-declarations-and-references)
- [Expression semantics](#expression-semantics)
- [Layer restrictions](#layer-restrictions)
- [Implementation and validation](#implementation-and-validation)

## Purpose

Give matching and attribute references a consistent vocabulary across routes,
access entries, grants, fault selectors, request forwarding, and metrics.
Preserve the existing authentication and authorization behavior while making
the configuration easier to read and validate.

| Previous syntax | Aligned syntax |
|----------------|-----------------|
| Route `path.exact` alongside condition `equals`. | Use `equals` for literal equality at every matching layer. |
| Fault selectors use maps; access selectors and grants use conditions. | Use condition lists with explicit expressions. |
| Grants put conditions directly under `attributes`. | Put conditions under `match.attributes`, matching other selector containers. |
| `present` has different meanings for headers and verified attributes. | Keep `present` for existence and introduce `nonempty` for nonempty scalar strings. |
| `equals-attribute` embeds the operand type in the expression name. | Use `equals` with `value_from.attribute`. |
| Source declarations use `from_source` and an overloaded `value`. | Use a typed `from` object. |
| Forwarding uses `from_attribute`; metrics use bare attribute names. | Use `from.attribute` for both. |

This is a direct rewrite of the current schema. Update examples and fixtures
together without retaining compatibility aliases.

## Condition syntax

A named condition keeps `name` and `expression`. Expressions that take an
operand use exactly one of `value` for a literal or `value_from` for a
reference. `value_from` initially supports only a declared attribute.

Proposed local grant:

```yaml
authorization:
  grants:
    - authenticator: internal-jwt
      match:
        attributes:
          - name: tenant_id
            expression: equals
            value_from:
              attribute: requested_tenant
          - name: role
            expression: in
            value: [reader, admin]
          - name: writer_id
            expression: nonempty
```

`tenant_id`, `requested_tenant`, `role`, and `writer_id` must be declared by
`internal-jwt`. If `requested_tenant` comes from a header, that header must also
appear in the access entry's selectors.

Routes have an implicit path target, so their condition omits `name`:

```yaml
routes:
  - methods: [GET]
    path:
      expression: equals
      value: /status
```

Fault selectors use the same named condition structure:

```yaml
fault_injection:
  enabled: true
  match:
    headers:
      - name: X-Inject-Fault
        expression: equals
        value: "true"
    attributes:
      - name: tenant_id
        expression: in
        value: [test-tenant]
  abort:
    http_status: 503
    percentage: 100
```

All conditions within a match must succeed. Any applicable grant can allow
access. Preserve the existing restrictions on overlapping access entries and
duplicate condition names.

Path rewrites retain their action-specific `path`, `prefix`, and `regex`
settings. Rewriting changes a value; matching evaluates a condition.

## Source declarations and references

Replace `from_source` and its associated `value` with a `from` object containing
exactly one source key:

| Source key | Operand | Available context |
|------------|---------|-------------------|
| `claim` | List of literal claim keys. | JWT authenticator attributes. |
| `fixed` | Nonempty literal string. | API and authenticator attributes. |
| `credential` | API-key credential attribute name. | API-key authenticator attributes. |
| `certificate` | `uri_san` or `dns_san`. | mTLS authenticator attributes. |
| `header` | Original request header name. | Authenticator and external service attribute declarations. |
| `attribute` | Declared attribute name. | External service inputs, forwarding, metrics, and comparison references. |

Proposed declarations within a JWT authenticator:

```yaml
attributes:
  - name: tenant_id
    from:
      claim: [organization, id]
  - name: requested_tenant
    from:
      header: X-Tenant
```

The source-reference structure is shared by `from` and `value_from`. Context
determines which source keys are allowed. For external service inputs,
`from.attribute` references an attribute declared by every selected local
authenticator and retains the existing requirement that the input name match
the attribute name.

Proposed route header mapping:

```yaml
processing:
  request_headers:
    - name: X-Scope-OrgID
      from:
        attribute: requested_tenant
```

Proposed API metric binding:

```yaml
metrics:
  labels:
    tenant:
      from:
        attribute: tenant_id
```

Fixed attributes use `from.fixed`, preserving their availability on APIs and
after authenticator verification. They cannot be local grant operands or
fault attribute sources.

Source values remain unchanged. Preserve literal claim-key paths, provider
isolation, and header safety rules. A separate source declaration is required
when another value is needed.

Explicit source objects add some YAML to simple mappings. In exchange,
extraction, forwarding, and comparisons use the same reference structure.

## Expression semantics

| Expression | Meaning | Operand |
|------------|---------|---------|
| `equals` | Scalar equals the operand. | One literal string or `value_from.attribute`. |
| `in` | Scalar equals any listed value. | Nonempty list of distinct strings. |
| `present` | Value exists; an empty header value still exists. | None. |
| `nonempty` | Value is a nonempty scalar string. | None. |
| `has` | JWT list contains one exact string. | One literal string. |
| `has-one-of` | JWT list contains any listed string. | Nonempty list of distinct strings. |
| `prefix` | Path begins with the operand. | One literal string. |
| `regex` | Complete path matches the RE2 expression. | One literal string. |

Keep scalar membership (`in`) distinct from list membership (`has` and
`has-one-of`). Preserve case-sensitive equality and fail closed for missing or
incorrectly typed values. Preserve each layer's existing literal-value
validation without trimming or coercing values.

Current header `present` becomes proposed `present`. Current grant `present`
becomes proposed `nonempty`. The stronger credential check is retained:
an empty string, list, number, boolean, or null cannot satisfy `nonempty`.

## Layer restrictions

Shared syntax has explicit expression and source limits in each context:

| Layer | Expressions for the initial rewrite |
|-------|-------------------------------------|
| Route path | `equals`, `prefix`, `regex`. |
| Access header selectors | `equals`, `in`, `present`. Credential headers allow only `present` with the matching authentication method. |
| Local grant attributes | `equals`, `in`, `nonempty`, `has`, `has-one-of`, with the existing source-type restrictions. |
| Fault header selectors | `equals` with a literal string. |
| Fault attribute selectors | `in` with a literal list of strings. |
| Forwarding and metrics | Declared attribute references. |

Local grant targets must still come from verified credentials. Attribute
equality stays within the same authenticator; a header reference on the right
must participate in request selection. List matching remains limited to
verified JWT list claims. Fault attribute matching requires verified scalar
sources across all protected entries.

Keep JWT providers isolated, authentication methods explicit, and mTLS
authentication at server scope. Keep external service header allowlists and
credential cleanup. External authorization continues to return an allow or
deny decision, with response header mutations rejected.

Keep Envoy terminology for transport and resource settings, including
`http_protocol`, `circuit_breakers`, and `admission_control`. Static bootstrap
changes continue to require an explicit Deployment rollout.

## Implementation and validation

1. Introduce typed source references and a shared condition structure in
   `pkg/api`. Use explicit validation rules for each consuming context.
2. Update loading, validation, and generation together. Check the pinned Envoy
   documentation when mapping expressions to native routes and filters.
3. Update `config.example.yaml`, the configuration reference, user guides,
   playground configuration, and scenario fixtures to the new schema.
4. Add focused checks for operand types, source availability, same-provider
   references, and expressions rejected outside their allowed contexts.
5. Verify empty header presence, nonempty credential checks, scalar and list
   membership, tenant equality, forwarding, metric labels, and fault selection
   preserve their current observable behavior.
6. Review any generated golden differences and run the checks required by
   [CONTRIBUTING.md](../../CONTRIBUTING.md), including runtime and full e2e tests.

The expected result is a smaller set of configuration patterns with unchanged
request routing and access decisions.
