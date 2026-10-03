# JWT processing implementation

Implementation plan for [RHOBS-1784](https://redhat.atlassian.net/browse/RHOBS-1784),
part of [RHOBS-1782](https://redhat.atlassian.net/browse/RHOBS-1782).

## Goal and current scope

The `RHOBS-1784` implementation provides JWT authentication, authorization
against original claims, and optional ordered attribute processing. It uses
native Envoy filters throughout. Keep code quality and valuable testing as
acceptance requirements, not follow-up work.

This document replaces the earlier design that translated attributes before
authorization. The revised runtime behavior is implemented on this branch.

Scope is JWT only. mTLS remains future work; preserve its example without
expanding its implementation or designing combined authentication flows.
Existing routing and server TLS behavior remain covered by regression tests.

Isolated probes against `envoyproxy/envoy:v1.39.1` confirmed native support for
nested claim extraction, literal dotted keys, optional values, ordered mappings,
unmatched-value passthrough, and required-header rejection. These probes establish
feasibility. They do not replace generator-backed JWT e2e tests.

## Behavior and implementation

The logical request flow is:

```text
Verify JWT
  -> Authorize using original claims
  -> Populate working attributes
  -> Apply processors in declaration order
  -> Check required header attributes
  -> Set route headers
  -> Forward upstream
```

### Authentication and authorization

- Retain native JWT verification for signature, issuer, audience, expiration, and
  not-before constraints. Accept bearer tokens from the Authorization header and
  remove the credential before forwarding.
- Keep each provider's verified payload in its own JWT metadata entry. Compile
  authorization attribute names into paths within that provider's payload.
  Authorization must never read transformed attributes or caller-supplied
  identity headers.
- `claim_path` remains a list of literal object keys. Missing, empty, null, or
  non-string application claims leave attributes unset. Do not coerce values or
  invalidate an otherwise valid JWT because an application claim is unavailable.
- Authorization conditions requiring absent attributes do not match. Preserve
  per-authenticator grants, per-API permissions, server policy combinations,
  default denial, and server isolation. An authorization denial never retries
  another identity.
- Support alternative JWT authenticators with distinct issuers on each server.
  Reject duplicate issuer bindings within a server, including bindings with
  different audiences. The same issuer may be configured on separate servers.
  Keep the existing single-JWT restriction for authentication `all_of`.
- Preserve local 404/405 behavior after successful authentication and existing
  native credential-failure responses. Missing required header attributes return
  403 at the later header check.

### Processing configuration

Add an optional ordered `processing` list to `Config`. Initially support only
`type: attribute-mapper`, with a name and attribute lookup tables:

```yaml
processing:
  - name: upstream-tenants
    type: attribute-mapper
    attributes:
      tenant_id:
        mappings:
          client-123: team-a
          client-456: team-b
```

Remove authenticator-level value mappings without a compatibility layer. Keep
strict YAML decoding and update the examples, fixtures, and public Go types
alongside the implementation.

- The processor list applies globally after authorization and before route header
  processing. It does not introduce server-specific processor bindings.
- Each processor performs one exact lookup per configured attribute. Entries in
  one lookup table must not chain into each other.
- Missing attributes are skipped. Unmatched values remain unchanged.
- Later processors consume earlier results and may overwrite the same attribute.
  Preserve declaration order. Lookup-table entry order has no meaning.
- Attributes and lookup values remain strings. Quote numeric-looking keys in
  examples. Do not add collision rejection or override warnings.
- Leave `routes[].processing.request_headers` as the explicit selection of
  upstream headers and their `from_attribute` sources.

### Native Envoy generation

Use native filters with separate responsibilities:

1. `jwt_authn` verifies the credential and exposes the original payload.
2. RBAC evaluates raw claims using the named authenticator's metadata and the
   selected API. Attribute aliases can be resolved during generation; no runtime
   extraction script is needed for authorization.
3. `set_filter_state` populates working attributes from the verified payload.
   Scope initialization to the server's bound authenticators.
4. An optional, separately named `set_filter_state` instance applies the ordered
   mappings after authorization.
5. A separate native RBAC instance checks the selected route's required header
   values after all processors have run.
6. Native header mutation removes caller-supplied managed headers and writes
   only the outputs declared by the selected route. The router forwards the
   request.

Use `auth_gateway.attributes.<name>` as the working filter-state keys and
`envoy.string` as their factory. Header output reads the final values through
`%FILTER_STATE(auth_gateway.attributes.<name>:PLAIN)%`. Keep original JWT metadata
unchanged throughout processing.

Generate guarded CEL expressions for literal claim-path traversal and mapping.
Missing or unsuitable claims must yield no working attribute. Set
`skip_if_empty: true` and omit empty formatter values so absent values do not
become placeholder strings such as `-`.

In the pinned Envoy version, CEL exposes `envoy.string` filter-state values as
bytes. Compare mapping sources using correctly escaped byte literals. Keep
string and byte-literal encoding in small, focused helpers. Generate one update
per attribute per processor so later processors see earlier updates without
chaining entries within a single lookup table.

A required header source must contain a usable value after processing. Return
403 before forwarding if it is absent or unsuitable for an HTTP header. Derive
these checks from the selected route's configuration. Routes without header
outputs have no such requirement. Retain validation of reserved header names.

Relax validation that requires every `any_of` authenticator to provide every
route header attribute. A referenced attribute must be declared by at least one
bound authenticator; availability for the actual request is checked at runtime.
Processing tables may mention attributes absent from a request or configuration.

Preserve the selected route throughout authorization and processing. Do not clear
the route cache. Include filters and resources only where needed: plain JWT
authorization must not acquire processing machinery unnecessarily.

### Envoy bootstrap and ECDS configuration

Keep JWT verification, authorization, route configuration, and attribute
extraction in native Envoy filters. When mappings are configured, load the
`set_filter_state` filter config through file-based ECDS. The config contains
both claim extraction and ordered mapping updates, so later processors consume
earlier results without depending on changes to the bootstrap.

Write the ECDS discovery response to `processing.yaml` in a separate
`<name>-processing` ConfigMap mounted at `/etc/auth-gateway/processing`. Envoy
watches the mounted directory. A mapping update changes only this ConfigMap; it
does not change `envoy.yaml`, the Deployment template, or the Pod identity.
Attribute initialization without mappings remains typed filter config in the
bootstrap. Do not attach a checksum annotation to the Deployment template.

Static bootstrap changes still need a Deployment rollout to take effect. A
similar ECDS delivery pattern may be evaluated for future API-key processing,
after selecting a filter and a secure source and rotation design for key
material. Do not add speculative API-key support to this implementation.

## Testing strategy

Test meaningful contracts at the layer that owns them. Unit tests check
configuration and generation decisions. E2e tests prove request behavior in the
pinned Envoy version. Do not implement a second processor inside tests.

### Case-based fixtures and reference output

Reorganize all configuration test data by case, including the existing routing
and server TLS cases:

```text
config/testdata/
  public-routing/
  route-lists/
  server-tls/
  jwt-auth/
  jwt-auth-with-headers/
  jwt-auth-with-mappings/
  jwt-auth-multiple-issuers/
```

Each case contains `config.yaml`, its supporting fixtures, and applicable
reference files such as `envoy.yaml.golden`, `kubernetes.yaml.golden`, and
`processing.yaml.golden`. Keep related inputs and outputs together rather than
using shared output-format directories. Use table-driven variations for small
validation differences instead of creating a folder for every assertion.

- Golden files are review artifacts. Remove whole-file equality assertions
  against generated YAML, manifests, and scripts.
- Keep `make update-golden` as an explicit regeneration command backed by a small
  dedicated generator. Remove the test `-update` flag and test-side file writes.
- Normal tests must not rewrite fixtures or reference files.
- Unit tests load their own case inputs. Keep a separate smoke test for the
  supported root example rather than using it as every test's fixture.
- E2e tests generate fresh configuration from inputs; they must not deploy
  checked-in golden output.

### Focused unit tests

Use case-driven assertions on decoded configuration and typed generated
resources. Cover:

- Configuration validation, references, defaults, and input immutability.
- Duplicate issuer bindings rejected per server, without a global issuer ban.
- Correct provider and literal claim-path references in authorization.
- Required filter ordering, route-specific header requirements, static
  attribute initialization, and the ECDS `set_filter_state` resource.
- No Lua filters or Lua resources in JWT cases; add the `set_filter_state`
  filter only when attributes or mappings require it.
- Mapping updates changing only the processing ConfigMap while leaving the
  bootstrap and Deployment template unchanged.
- Relevant routing, server TLS, Kubernetes mount, and service-port contracts
  currently covered by structural assertions.

Avoid exact generated-expression comparisons, source substring checks, exhaustive
assertions on incidental defaults, and large helpers that hide what a case
proves. Preserve useful existing assertions when removing snapshot comparisons.

### E2e behavior

Use real signed JWTs, controllable local JWKS endpoints, and
`envoyproxy/envoy:v1.39.1`. Cover these distinct behaviors:

| Case | What it must prove |
| --- | --- |
| Plain JWT authorization | Valid credentials can access an allowed API without mappings or header output; invalid credentials and denied grants fail. |
| Direct headers | Verified raw attributes reach the upstream only as the configured headers. |
| Mappings | Authorization evaluates the original identifier while the upstream receives the transformed value. |
| Ordered processors | Later processors observe earlier changes; intentional overwrites work; each processor performs one lookup. |
| Unmatched values | An authorized value with no mapping entry reaches the upstream unchanged. |
| Missing attributes | Unused missing claims succeed; missing authorization attributes deny; missing required header attributes return 403. |
| Literal values and paths | Nested paths, literal dotted keys, and escaped mapping values work without coercion. |
| Multiple issuers | The same raw value cannot borrow another issuer's grant or attribute source; server trust remains isolated. |
| Managed headers | Caller-supplied and duplicate managed headers are replaced or removed; bearer credentials are removed. |
| Mapping update | Applying a changed processing ConfigMap reloads the mapping through ECDS without replacing the Pod; authorization still uses the original claim and the upstream receives the new mapped value. |

For the mapping update case, change an output value to one that would not
satisfy the raw grant if authorization accidentally read transformed values.
Apply the changed processing ConfigMap, then verify the request remains
authorized, emits the new value, and keeps the same Pod identity.

Assert HTTP outcomes and backend observations, including that denied requests do
not reach the backend. Retain the useful existing JWT failure, HTTP/HTTPS,
JWKS rotation, cache, outage-isolation, and recovery coverage. Keep lifecycle
scenarios isolated from access/processing scenarios so failures are diagnosable.

## Code quality and documentation

Keep configuration validation, native filter generation, and resource packaging
focused and readable. Use typed Envoy configuration and small helpers with clear
ownership. Preserve declared list order and deterministic serialization of
unordered maps. Avoid speculative processor frameworks and mTLS abstractions.

Remove obsolete Lua generation, resource handling, snapshot assertions, fixtures,
and documentation as their replacements land. Do not retain two implementations
of the same JWT flow. Keep comments concise and explain only non-obvious
behavior.

Update the JWT example's policies to allow original identifiers and move all
translations into processing. Supply mappings for both example issuers. Remove
comments that imply mapping is part of authentication or authorization.

Keep `docs/jwt-auth.md` linked from the README. Document plain JWT
authorization, direct headers, mappings, multiple issuers, missing attributes,
and ECDS reload behavior for mapping changes. Include concise flow diagrams and
working examples. Keep
user documentation aligned with the implementation and distinct from this
handoff plan. Mention mTLS only as future work.

## Completion status and follow-up

The implementation reorganizes fixtures by case, generates reviewable reference
files, uses native JWT/RBAC/`set_filter_state`/header filters, and removes the
superseded Lua path. The focused JWT and complete e2e suites remain required for
handoff after changes to filter generation or Kubernetes packaging.

Completion requires:

- The updated JWT example loads and generates valid configuration.
- Fixtures and reference outputs are grouped by case, with no whole-file golden
  comparisons in tests.
- JWT behavior uses native Envoy filters and has meaningful e2e coverage.
- Mapping updates reload through ECDS without changing the bootstrap, Deployment
  template, or Pod identity, while authorization continues to use the original
  claim.
- Documentation describes the implemented JWT flows and their failure behavior.
- `make test` and `go vet ./...` pass.
- During development, use the focused JWT e2e group:
  `make -C e2e test GINKGO_ARGS='--label-filter=jwt'`.
- Before implementation handoff, run the complete existing suite with
  `make -C e2e test`, because generation changes affect shared infrastructure.
- Regenerate and review reference output, run `git diff --check`, and record the
  checks actually run and any remaining limitations. Do not claim a runtime check
  passed on the strength of generated configuration or a golden file.
