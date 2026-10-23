# Phased improvement plan

Review baseline: `934f4e0`, reviewed on 2026-10-23.

Status: in progress. D1's implementation and acceptance checks are done;
[PR #17](https://github.com/rhobs/auth-gateway/pull/17) awaits upstream review
and merge. All other items remain planned.

This plan covers six confirmed defects (D1-D6), two gaps (G1-G2), and three
simplification opportunities (S1-S3). The findings apply to the generator and
its generated Envoy and Kubernetes configuration at the review baseline.

## Priorities and sequence

- P0: address identity isolation first.
- P1: correct generated configuration, deployment behavior, and operational
  gaps before further feature work.
- P2: simplify after the affected behavior has regression coverage.

| Phase | Outcome | Items |
| --- | --- | --- |
| 0 | Resolve conflicting authentication scope guidance | G1 |
| 1 | Isolate authenticated identities and gateway workloads | D1 (implementation done), D2 |
| 2 | Generate configuration that Envoy accepts at realistic sizes | D3, D4 |
| 3 | Make termination, restricted admission, and metrics predictable | D5, D6, G2 |
| 4 | Reduce duplication and dependency overhead | S1, S2, S3 |
| 5 | Complete documentation, rollout guidance, and verification | All |

Phases order the work by risk. Independent fixes can proceed separately.
G1 affects decisions about mTLS; it does not block unrelated fixes. Complete
the identity and generator fixes before refactoring their shared code.

## Constraints for every phase

- Preserve the checked-in version 1 schema. Record any proposed scope change
  separately; do not introduce aliases or migration code as part of a fix.
- Keep authentication, authorization, and attribute mapping in native Envoy
  filters. Lua remains limited to per-API response counters.
- Keep mapping data in `processing.yaml` and the separate `<name>-processing`
  ConfigMap. Mapping-only updates must preserve the bootstrap, Deployment
  template, and Pod identity.
- Document explicit Deployment rollouts for static bootstrap changes.
  Generated Deployments continue without checksum annotations.
- Follow [CONTRIBUTING.md](../CONTRIBUTING.md) for test ownership and golden
  updates. Use test-owned fixtures, valid baselines, and focused assertions.
- Keep the schema, [full example](../config.example.yaml),
  [configuration reference](configuration-reference.md), generated output,
  and relevant guides aligned when behavior changes.

## Phase 0: Resolve the supported authentication contract

### G1. Reconcile mTLS scope guidance (P1, documentation and scope gap)

**Evidence:** [AGENTS.md](../AGENTS.md) says client-certificate mTLS is
unsupported. The implementation, tests, [README](../README.md), and
[mTLS guide](auth/mtls.md) expose and exercise it.

**Work:** Record an explicit maintainer decision about the supported
authentication contract. Identify the implementation, schema, examples,
guidance, and tests affected by that decision. This plan does not authorize
adding support or removing existing functionality.

**Acceptance and validation:**

- Guidance and user-facing documentation state one consistent contract.
- Any behavior or schema changes follow an explicitly agreed scope and have
  corresponding generated-output and observable behavior coverage.
- D1's identity-selection rules are documented for the supported combinations.

## Phase 1: Fix identity and workload isolation

### D1. Prevent attributes from different identities being combined (P0, confirmed)

**Status: Done (implementation and acceptance checks, 2026-10-23).**
[PR #17](https://github.com/rhobs/auth-gateway/pull/17) awaits review and merge.

**Evidence at the review baseline:** [Attribute initialization](../config/cel.go)
wrote attributes in authenticator priority order and used `skip_if_empty`. An
absent attribute from a higher-priority identity could retain a lower-priority
identity's value.

A probe against the pinned Envoy image used JWT subject authorization and a
required tenant header:

| Credentials | Result |
| --- | --- |
| Authorized JWT subject, missing tenant | 403 |
| Trusted client certificate, without the JWT authorization grant | 403 |
| Both credentials together | 200, certificate tenant forwarded |
| JWT with its own tenant, plus certificate | 200, JWT tenant forwarded |

**Work:** Select the identity for mixed `any_of` authentication before
initializing its working attributes. Missing or empty attributes must remain
missing for that selected identity. Preserve the current JWT -> mTLS ->
API-key priority wherever that combination remains supported after G1.
Keep `all_of` requirements explicit and separate.

**Acceptance and validation:**

- [x] Combining independently insufficient credentials cannot create a valid
  request by borrowing attributes across identities.
- [x] Unit tests cover generated selection and initialization for supported
  combinations, including missing, empty, and conflicting attributes.
- [x] Focused gateway e2e tests assert the selected identity's forwarded headers
  and demonstrate that denied requests never reach httpbin.
- [x] Authorization continues to use original values before attribute mapping.

**Dependency:** Resolve G1 before changing mTLS-specific support or semantics.
D1 enforces the existing documented authenticator priority. The supported
authentication contract remains a separate decision under G1.

**Delivered:** Native filter state finishes identity selection before copying
attributes and guards every working-attribute update with that selection.
Missing, empty, non-string, and undeclared values stay unset. See the
[unit regressions](../config/identity_test.go) and
[gateway regressions](../e2e/identity_isolation_test.go). Documentation, the
full example, and affected goldens are aligned.

**Validation:** `make test`, `make lint`, tagged e2e/runtime compilation,
framework tests, `make test-runtime`, and `make e2e` passed on 2026-10-23
(80/80 Kind specs). The five focused gateway specs reproduced three attribute
leaks before the fix and pass afterward.

**Rollout:** Regenerate the static bootstrap and explicitly roll out gateway
Deployments to apply the fix.

### D2. Give each Kubernetes gateway stable, distinct selectors (P1, confirmed)

**Evidence:** [Kubernetes labels](../config/kubernetes.go) use the fixed name
`auth-gateway` and `node.cluster` as the instance. Two differently named
gateways using the default cluster value have identical Deployment and
Service selectors in one namespace. Changing `node.cluster` also changes an
immutable Deployment selector.

**Work:** Base selectors on stable Kubernetes gateway identity, independent
of Envoy's node cluster. Keep Deployment selectors, Pod labels, and Service
selectors consistent. Document how existing Deployments with the old
immutable selectors must be recreated or replaced during upgrade.

**Acceptance and validation:**

- Unit tests show that differently named gateways in the same namespace have
  distinct selectors, including when they share `node.cluster`.
- Changing only `node.cluster` preserves the Deployment selector.
- A focused Kind scenario verifies that each Service selects only its own
  gateway Pods and requests reach the intended gateway.
- Upgrade instructions explain the immutable-selector constraint and the
  replacement sequence; generated manifests do not imply an in-place update
  will succeed.

## Phase 2: Remove generated-expression limits

### D3. Replace deeply nested mapping conditionals (P1, confirmed)

**Evidence:** [Mapping expressions](../config/cel.go) add a nested conditional
for each entry. Go validation and generation succeeded with 25 mappings, but
Envoy rejected the processing ECDS resource with:

```text
Not able to parse expression: CANCELLED:
Expression recursion limit exceeded. limit: 32
```

Authenticated requests returned 500. A four-entry baseline returned 200 with
the expected mapped value.

**Work:** Generate a shallow native CEL lookup. Preserve deterministic
output, literal escaping, unmatched values, processor order, and authorization
against original values. Establish a tested capacity with the pinned Envoy
image rather than relying on Go generation succeeding.

**Acceptance and validation:**

- Unit tests cover generated lookups, absent and unmatched values, escaping,
  and ordered processors.
- Runtime fixtures with 25 and 100 entries load successfully and produce the
  expected mappings. Document and validate any remaining hard limit.
- A valid file-based ECDS update changes observed mappings without restarting
  Envoy. Keep malformed-update rejection and retention outside this suite.
- Generated-output tests confirm that changing only mapping data changes
  only the processing resource and its ConfigMap.

### D4. Reduce API-key extraction regex complexity (P1, confirmed)

**Evidence:** [API-key attribute extraction](../config/api_keys.go) repeats
the complete credential attribute layout in each extraction and identity
check. Configurations with two and six attributes validated in Envoy. Ten
attributes named `attribute00` through `attribute09` failed with:

```text
RE2 program size of 141 > max program size of 100
```

Twenty attributes produced size 291. Go generation succeeded in each case.
The boundary depends on the names and pattern, so ten is not a universal
attribute limit.

**Work:** Simplify extraction and identity checks within native filters.
Preserve safe attribute encoding, missing-attribute behavior, authentication
decisions, and removal of credentials and internal identity headers.

**Acceptance and validation:**

- The previously failing ten- and twenty-attribute fixtures validate and start
  against the pinned Envoy image, with correct attribute extraction.
- Unit coverage includes representative attribute names, encoded values,
  absent attributes, and deterministic generated output.
- Any remaining limit produces an actionable Go validation error before
  generating an unusable deployment.
- Gateway e2e coverage verifies forwarding and credential removal. Denied
  requests never reach the backend; request-decision tests remain read-only.

## Phase 3: Close operational gaps

### D5. Drain Envoy explicitly during termination (P1, confirmed)

**Evidence:** The [generated lifecycle hook](../config/kubernetes.go) sleeps
for five seconds within a 30-second termination grace period. It does not
initiate draining. In a runtime probe, an eight-second backend request was
active when SIGTERM followed the five-second delay; the client received EOF
about 121 ms after SIGTERM. The existing drain-oriented unit test checks the
sleep command rather than successful draining.

**Work:** Generate an explicit Envoy drain sequence. Coordinate readiness,
endpoint propagation, drain duration, and the overall termination budget.
Use commands available in the pinned image. Define the bounded behavior for
requests or streams that exceed the grace period.

**Acceptance and validation:**

- Unit tests verify the generated lifecycle operation and sufficient grace
  budget for the complete sequence.
- Runtime tests demonstrate that an active eight-second request completes
  during orderly termination within the selected budget.
- Runtime coverage checks bounded shutdown and the chosen behavior for new
  connections during draining. These Envoy semantics belong in the runtime
  suite.
- Operational documentation explains the drain and maximum termination time.

### D6. Make the default Pod pass restricted admission (P1, confirmed)

**Evidence:** A server-side dry-run of the generated Pod in a restricted
namespace was rejected. The [collector container](../config/kubernetes.go)
lacks `allowPrivilegeEscalation: false`, a drop of `ALL` capabilities, and
`runAsNonRoot`. Envoy and the collector also lack seccomp configuration.

**Work:** Apply consistent container hardening and Pod-level
`seccompProfile: RuntimeDefault`. Verify the collector image's user and
filesystem needs before choosing its security context.

**Acceptance and validation:**

- Unit tests assert the required Pod and container security settings for
  configurations with and without the collector.
- Server-side admission succeeds in a restricted namespace.
- Both containers start and become usable with the generated settings;
  gateway requests, metrics, and configured trace export still work.
- Admission and startup checks use an isolated Kind namespace and the
  existing framework's lifecycle and cleanup support.

### G2. Bound request metric cardinality (P1, operational gap)

**Evidence:** [Response counters](../config/observability.go) include dynamic
attribute values in counter names. Length and character checks do not bound
the number of distinct combinations. Each combination creates a counter
retained until Envoy restarts. Caller-controlled header attributes can create
unbounded combinations, including on denied requests.

**Work:** Record a cardinality policy before implementation. Choose bounded
values, a fixed overflow bucket, or an enforced cardinality ceiling. Enforce
the bound where Envoy counters are created; dropping exported series later
does not bound Envoy's counter allocation. Work within version 1 unless a
schema change is separately agreed.

**Acceptance and validation:**

- Document the bound, its scope, overflow behavior, and counting semantics
  for allowed and denied requests.
- A runtime test sends many distinct attribute values and verifies that
  counter allocation stops growing at the documented bound.
- Observable metrics coverage checks totals and overflow behavior, including
  denied requests, without changing authorization decisions.
- Update the reference and example if the agreed design changes their
  configuration contract.

**Dependency:** Complete the policy decision before implementing a limit.

## Phase 4: Simplify after behavior is protected

### S1. Combine allowed methods in one generated route (P2, opportunity)

**Evidence:** [Route generation](../config/generate.go) emits a separate
route for each allowed method, duplicating actions, metadata, and filter
configuration.

**Work:** Evaluate one route per configured path with a combined, anchored
method matcher. First decide how to preserve or intentionally change existing
per-method route statistics, names, and stat prefixes.

**Acceptance and validation:**

- Generated output contains fewer repeated route objects for a multi-method
  fixture, with the reduction recorded in the change.
- Unit tests preserve route order, exact method matching, 404/405 behavior,
  and the `Allow` header, including overlapping paths and method sets.
- Observable behavior preserves rewrites, authentication, authorization,
  forwarded requests, metrics, and fault/admission selection. Keep Envoy
  admission semantics in the runtime suite.
- Document any accepted statistics change before updating goldens.

**Dependency:** Settle the statistics contract before changing route shape.

### S2. Resolve references once and reuse indexes (P2, opportunity)

**Evidence:** Generation repeatedly searches authenticators, policies, and
APIs and contains separate JWT-only and mixed-auth paths.

**Work:** Build internal indexes during configuration resolution and pass
resolved references to generation. Consolidate paths where they implement
the same behavior. Keep intentional authentication differences explicit.

**Acceptance and validation:**

- Unknown references retain useful validation errors and deterministic
  ordering.
- Resolution and generation preserve input immutability.
- Existing goldens and observable behavior remain unchanged for this
  refactor; focused tests cover any newly shared resolution behavior.
- Repeated reference scans are reduced without adding a public schema or
  another independently maintained representation of configuration.

**Dependency:** Land D1, D3, and D4 first so the refactor preserves corrected
behavior rather than embedding their defects in shared code.

### S3. Isolate lint tooling dependencies (P2, opportunity)

**Evidence:** The [main Go module](../go.mod) carries golangci-lint and its
large dependency graph. [e2e/tools](../e2e/tools/go.mod) already demonstrates
a separate tooling module.

**Work:** Move lint tooling to a dedicated Go module. Update the
[Makefile](../Makefile), CI, and contributor instructions to invoke it from
the correct module while preserving pinned versions.

**Acceptance and validation:**

- The application module no longer requires dependencies solely for lint
  tooling; the tooling module retains the pinned linter version.
- `make tools`, `make lint`, and existing CI entry points work from a clean
  checkout without a globally installed linter.
- Unit tests and tagged compilation still pass, and the application
  dependency changes are reviewed separately from tool dependencies.

## Phase 5: Verify and document each delivered change

Keep fixes and independent refactors in small reviewable changes. Update this
plan as acceptance criteria are met and link the corresponding PRs. Review
every intentional golden change using the workflow in
[CONTRIBUTING.md](../CONTRIBUTING.md).

For implementation changes, run relevant focused checks and the required
handoff suite:

```sh
make test
make lint
go test -tags=e2e,envoyruntime -run '^$' ./...
go test -tags=e2e ./e2e/internal/framework
make test-runtime
make e2e
git diff --check
```

Runtime checks are required for changes whose acceptance criteria depend on
Envoy parsing, reloads, draining, or counter allocation. Exercise valid
file-based ECDS/SDS reloads; do not add malformed-update rejection or
retention tests. Use the existing Kind rotation scenario for projected Secret
behavior.

The reviewed source passed unit tests, lint, tagged compilation, framework
tests, the runtime suite, and all 75 Kind e2e specs. The focused probes above
exposed cases outside that coverage. Those baseline results do not establish
that the planned fixes are complete.

For documentation-only updates to this plan, check relative links and
whitespace:

```sh
sh scripts/check-markdown-links.sh
git diff --check
```
