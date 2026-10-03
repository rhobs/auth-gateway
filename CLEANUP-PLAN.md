# Code, test, and documentation cleanup plan

Updated: 2026-10-03.

This is the approved implementation plan for repository cleanup. It records the
review findings, required changes, behavior to preserve, and verification
criteria. The implementation status and actual check results are in Section 9.
[HANDOVER.md](HANDOVER.md) contains the shorter status summary.

## 1. Outcome and constraints

Review and simplify the whole repository: production code, tests, test
infrastructure, fixtures, examples, documentation, and local build tools.

| Area | Required outcome |
| --- | --- |
| Code quality | Clear control flow, useful errors, correct ownership of mutable data, and small helpers with a clear purpose. |
| Code organization | Every receiver method is in the file that declares its receiver type. Related code stays together in the consolidated layout. |
| Duplication | Shared behavior has one implementation. Repeated strings and identifiers used by code and tests have named constants. |
| Linting | One documented local command checks production code and tests, including tagged code. |
| Tests | Every test and table case protects a distinct API behavior or necessary test-framework behavior. Remove duplicate and low-value checks after identifying surviving coverage. |
| Documentation | Configuration authors can generate, deploy, configure, and update the gateway from clear instructions. Envoy implementation details have a separate technical home. |

Apply these constraints throughout the work:

- Preserve public Go signatures, YAML fields, defaults, generated resource
  names, and runtime behavior. Record proposed API changes separately.
- Keep the consolidated layout. Do not split large files into many small files
  or turn methods into free functions to bypass the receiver placement rule.
- Keep golden regression checks. Normal tests must not update golden files.
- Use explicit YAML snippets or fixtures. Do not construct test YAML with
  string replacement.
- Add local linting only. Do not add a CI workflow.
- Use simple technical English (STE), concise comments, and ASCII punctuation.
- Keep dependency and image versions stable unless a demonstrated compatibility
  problem requires a separate change.
- Keep mTLS authentication and other new authentication features outside this
  cleanup. The mTLS example remains clearly marked as future work.

These decisions replace the older permission to make breaking API changes and
the instruction in `AUTH-PLAN.md` to avoid whole-file golden comparisons.

## 2. Starting state and work already done

This section records the state when the plan was drafted. Its interim
verification notes are superseded by Section 9.

The working branch is `code-quality-cleanup`, based on
`production-configuration` at `8be60ba` (`Consolidate request controls config`).
No new commits or pushes had been made when this review started. The user then
requested a commit of all pending changes. `go.mod` requires Go 1.26.0; the
local toolchain used during the earlier work was Go 1.26.6.

The earlier implementation work changed 11 existing files and added
`.golangci.yml`:

| Files | Change already made | What remains |
| --- | --- | --- |
| `e2e/jwt_test.go` | Removed two calls to the undefined `setGatewayImage` helper. The fixtures already specify the pinned Envoy image. | Compile the tagged suites and confirm both scenarios use the intended fixture image. |
| `config/config.go`, `config/servers.go`, `config/auth.go`, `config/trust.go` | Moved 11 `Config` receiver methods into `config/config.go` and adjusted imports. | Check the moves, group the methods, and review the remaining helpers. |
| `e2e/internal/framework/environment.go`, `kubernetes.go`, `cert_manager.go`, `forward.go`, `diagnostics.go` | Moved 18 `Environment` receiver methods into `environment.go` and adjusted imports. | Check compilation, finish file organization, and retain coherent helpers beside their owners. |
| `Makefile`, `.golangci.yml` | Added `make lint`, a formatting check, and golangci-lint v2.14.0 invoked through version-pinned `go run`. | Run lint, fix findings, and document the command. |

The linter was downloaded and built. Its version command succeeded. This does
not establish that its configuration or the repository passes lint.

**The implementation changes above have not been compiled, tested, or linted.**

The following results apply only to the tree before those changes:

| Check | Earlier result |
| --- | --- |
| `go test ./...` | Passed. |
| `go vet ./...` | Passed. |
| `go test -tags=e2e ./e2e/internal/framework` | Passed. |
| `go test -tags=e2e,envoyruntime -run '^$' ./...` | Failed on the two undefined `setGatewayImage` calls. |
| Live Kind e2e and pinned-image runtime tests | Not run in this session. |

The earlier documentation work replaced `HANDOVER.md` with a summary. This new
document supplies the detailed plan. No further implementation changes were
made while preparing this document.

The final commit review also found `AUTH-PLAN.md` deleted from the workspace.
Its content was read before deletion and informed this plan. Include the
deletion in the requested commit. For the remaining documentation merge, read
the former file with `git show 8be60ba:AUTH-PLAN.md`. The mTLS example still
references that deleted document; repairing the reference is pending.

A temporary method-moving script was created at
`/private/tmp/auth-gateway-refactor.go`. If it still exists, do not rerun it.
Review the current diff and make any further changes directly.

## 3. Behavior that must remain stable

Use this table when deciding whether a cleanup changes the contract.

| Area | Required behavior |
| --- | --- |
| Loading | `Load` accepts exactly one strict YAML document. Unknown fields, duplicate fields, invalid syntax, unsupported schemas, and extra documents are rejected. Duration errors identify the relevant field. |
| Defaults and ownership | Defaulting, validation, and generation preserve caller-owned maps, slices, and pointers. Nil, empty, and explicit-zero values keep their existing meanings. Supplied resource maps are not merged with defaults. |
| Timeout inheritance | Listener values feed API and route overrides during resolution. `Load` keeps omitted API and route timeout overrides nil. Reusing a loaded configuration must still resolve later overrides correctly. |
| Routing | Exact host bindings, server-scoped API exposure, API binding order, route order, explicit methods, exact/prefix/regex matches, and rewrites remain stable. Local 404 and 405 responses retain the correct combined `Allow` header. |
| JWT and authorization | Verification uses the selected server's providers. Grants use the named provider's original verified claims and selected API. Another issuer cannot satisfy that grant. Authorization runs before attribute transformation. |
| Attributes and headers | Claim-path segments are literal keys. Missing or unusable attributes remain unset. Mapping tables perform one lookup per processor; later processors see earlier results. Unmatched values pass through. Required headers are checked after processing. Managed caller headers are replaced, and bearer credentials are removed before forwarding. |
| Native Envoy generation | Preserve the conditional native filter chain and fixed request-control header removal. With Envoy 1.39.1, `envoy.string` values are bytes. Unmatched mappings use `skip_if_empty`. Do not restore Lua or CEL `string(bytes)`. |
| Transport trust | Upstream and JWKS TLS verify certificate trust and endpoint identity. Preserve system trust, custom file trust, Kubernetes CA references, DNS SNI, and IP SAN behavior. Distinct authenticators retain separate JWKS clusters and caches. |
| Updates | Mapping-value changes update only the processing ConfigMap and reload through ECDS. Downstream certificate/key changes reload through SDS. Static configuration and CA changes require an explicit rollout. The Deployment has no generated checksum annotation. |
| Kubernetes and telemetry | Preserve shared listener ports, HTTP/HTTPS Service selection, directory projections without `subPath`, mount deduplication, loopback-only admin access, metrics exposure, and error access logging. |
| Production settings | Preserve timeout boundaries, explicit HTTP protocol selection, resource quantity validation, exact heap-budget comparisons, opt-in overload controls, and explicit Envoy worker configuration. A CPU limit does not imply a worker count. |

## 4. Implementation sequence

Complete the phases in order. Each phase has a concrete exit condition. Keep
changes reviewable and record actual results in this document as work completes.

### Phase A: establish the state of the partial implementation

1. Read the current diff before editing. Preserve unrelated local work.
2. Run the unit tests, tagged compilation, and framework tests listed in
   section 8. Check the moved methods and removed helper calls first.
3. Run `make lint` to establish the actual findings. The duplication findings
   in this plan came from source review; they are not a claimed linter report.
4. Fix problems introduced by the partial changes before broader cleanup.
   Check that no moved method body or public signature changed unintentionally.

Exit condition: the partial moves compile, existing tests have a recorded
result, and lint findings are known. Do not carry an unexplained failing
baseline into test deletion or golden regeneration.

### Phase B: organize code by ownership

The receiver rule applies to value and pointer receivers, private and public
types, production code, and test infrastructure.

| Owning file | Types and code that belong there |
| --- | --- |
| `config/config.go` | `Config` and its methods, plus the existing `Listener`, `Upstream`, `HTTP2Options`, and `OverloadConfig` types and their methods. Keep loading, defaulting, validation, and effective-configuration resolution grouped clearly. |
| `config/servers.go` | `Server`, `ServerTLS`, their methods, and server-specific TLS/mount helpers. `Config` methods now live in `config.go`. |
| `config/auth.go` | Authentication, authorization, and processing types; their validation and domain-specific cloning helpers. |
| `config/jwks.go` | `JWKSConfig` and its methods, plus its closely related configuration helpers. |
| `config/trust.go` | `TrustedCA`, `CAConfigMap`, their methods, and trust/verified-TLS helpers. |
| `config/duration.go` | `Duration`, `durationYAMLError`, their methods, and duration parsing/error-path helpers. |
| `config/kubernetes.go` | `KubernetesResources`, `KubernetesMetrics`, their methods, and resource packaging/projection helpers. |
| `config/generate.go` | Envoy generation and its cohesive private helpers. Keep authentication, routing, transport, and serialization sections easy to find. |
| `config/metrics.go`, `config/access_log.go` | Collector configuration and access-log generation respectively. Put general Kubernetes resource-naming helpers with resource packaging when consolidating helpers. |
| `e2e/internal/framework/environment.go` | `Environment` and all its methods, grouped by lifecycle, resource access, forwarding, and diagnostics. |
| `e2e/internal/framework/forward.go` | `requestContextTransport` and `RoundTrip`, plus coherent Pod/port-selection helpers. |
| `e2e/jwt_test.go` | `jwtE2E`, its methods, JWT scenario setup, protocol clients, and assertions. |

Specific remaining organization work:

- Framework `kubernetes.go` now contains only `fieldManager` and
  `deploymentFailed`. Move both beside lifecycle operations in
  `environment.go`, then remove the redundant file.
- Inspect the remaining free functions in `cert_manager.go` and
  `diagnostics.go`. Retain a file when its helpers have a coherent purpose.
  Move orphaned helpers beside their only caller when that improves navigation.
- Keep protocol clients, fixture shaping, and assertions in the e2e package.
  Keep Kubernetes lifecycle, port forwarding, and diagnostics in the framework.
- Large files are not, by themselves, defects. After the earlier moves,
  `config.go` has about 1,250 lines, `generate.go` about 1,090, and
  `environment.go` about 610. Use clear ordering and remove duplication before
  proposing more files.

Exit condition: each receiver type and its methods share a file, no obsolete
stub files remain, and the layout preserves the selected consolidation.

### Phase C: simplify helpers and defaulting

The following duplication has been identified in the source:

| Current code | Planned action | Constraint |
| --- | --- | --- |
| `contains` in `generate.go` | Use `slices.Contains`. | Keep the same membership semantics. |
| `equalStringSlices` in `auth_test.go` | Remove it with the duplicate filter-order check, or use `slices.Equal` if still needed. | Ordered filter comparisons must remain ordered. |
| `cloneSlice` and `cloneMap` in `auth.go` | Use `slices.Clone` and `maps.Clone` for shallow copies. | Preserve nil/empty semantics and all necessary nested copying. |
| `defaultUint32` in `config.go` and generic `defaultValue` in `duration.go` | Use one generic pointer-default helper. | Preserve explicit zero and return independent pointers. |
| `sortedKeys`, `sortedFileNames`, and test `fileNames` | Use a consistent standard-library approach such as `slices.Sorted(maps.Keys(values))`; retain a wrapper only if it adds domain meaning. | Sort unordered map output. Preserve user-declared list order. |
| `ptrInt32` in `e2e/jwt_test.go` | Use the Go 1.26 pointer construction already used elsewhere. | Keep the minimum Go version unchanged. |
| `readFile`, `readFixture`, `loadConfigCase`, `loadAuthExample`, and repeated inline loading | Give file reading and fresh fixture loading one clear implementation in the existing test files. | Do not hide scenario mutations or expected results in a generic test framework. |
| Repeated Service-port collection in Kubernetes tests | Use one focused extraction helper or one scenario table. | Retain distinct HTTP-only, mixed, and HTTPS-only behavior. |

Preserve domain-specific deep cloning. JWT audiences, claim paths, processor
mapping maps, grant attribute slices, server bindings, route processing,
timeouts, CA references, Kubernetes resources, and optional numeric values can
all contain mutable nested data. A shallow standard-library copy alone is not
a replacement for those recursive copies.

`Load` currently calls `withDefaults`, then `Validate` calls `resolveConfig`,
which defaults again. This is a simplification candidate, with an API constraint:
`resolveConfig` materializes inherited route timeouts, while `Load` returns
unresolved API/route overrides. Share a private validation/resolution path only
if it can validate a defaulted private copy and preserve the value returned by
`Load`. Do not replace the return value with the fully resolved configuration.
If avoiding the extra copy adds more complexity than it removes, retain it and
record that decision.

Review generator duplication by meaning, not by appearance. In particular,
`celStringLiteral` and `celBytesLiteral` target different CEL types. Preserve
their escaping behavior unless the literal-key and escaped-value scenarios
prove a common implementation is safe.

Exit condition: redundant helpers are removed, nested ownership and inheritance
remain covered, and repeated generation produces the same complete output.

### Phase D: finish constants and local linting

Use constants at the narrowest useful scope. Reuse existing constants before
adding new ones. Prefer standard-library or dependency constants when they
already describe the value.

| Values to consolidate | Ownership and use |
| --- | --- |
| Envoy filter names and TLS transport-socket name | Owning generation/trust code; reuse in focused tests. Keep the existing `requestControlsFilterName` and other named filter constants. |
| `envoy.yaml`, processing filenames/directories, and generated-file comment header | Owning generation/packaging code; use in generation, projection, runtime checks, and tests. |
| Authorization/bearer identifiers, HTTP methods, managed header names, and metadata keys | Protocol owner; use standard HTTP method constants where appropriate. |
| Kubernetes port, container, volume, resource suffix, and TLS key names | Resource owner; preserve the exact generated names and paths. |
| Fixture names, hostnames, issuer names, tenant IDs, and other repeated test identities | Test package constants. Keep values used only by tests out of the public production API. |

Keep YAML snippets and golden files explicit and readable. Shared constants
must not make every expected result depend on the same code as the result under
test. Retain independent golden output and meaningful public-behavior checks.
Do not create an exported constants API solely to satisfy tests.

The current lint configuration is a starting point:

- golangci-lint v2.14.0, pinned in `Makefile`.
- Formatting checked by `gofmt -l`; `make lint` fails when formatting is needed.
- Tests included, with `e2e` and `envoyruntime` build tags.
- Read-only module resolution and a five-minute timeout.
- `govet`, `staticcheck`, `errcheck`, `ineffassign`, `unused`, `goconst`, and
  `dupl` enabled.
- `goconst` checks two or more occurrences, including call arguments.
- `dupl` uses a 150-token threshold.

Check that this configuration is accepted by the pinned version. Resolve real
findings in production code and tests. Handle useful errors, especially file,
HTTP, and cleanup errors, with enough context to diagnose a failure. If a
suppression is necessary, scope it to the specific finding and explain why.
Do not disable a whole test tree or introduce opaque abstractions merely to
satisfy the duplicate-code threshold.

Exit condition: `make lint` passes on all configured code, its command is
documented, and no unrelated dependency or CI changes are introduced.

## 5. Test review and consolidation plan

Review every test function and every table entry. For each one, identify the
input or event, the API behavior under test, and the observable expected result.
Remove a case only when another named case protects the same contract, or when
the case checks an implementation detail with no useful failure signal.

Maintain the removal-to-surviving-coverage mapping in this plan during
implementation. A table-driven test does not make duplicate cases useful.
Shared setup also does not make two different behaviors duplicates.

### 5.1 Loading, defaults, validation, and ownership

| Current tests or finding | Required action and final owner |
| --- | --- |
| `TestLoadRejectsInvalidYAML` in `config_test.go` accepts any error; its unknown/duplicate-field documents are otherwise incomplete. | Keep strict-loading coverage in `config_test.go`. Use otherwise valid inputs where applicable and assert the parser category or relevant field. Validation of an incomplete document must not mask a parser regression. |
| `TestDurationYAMLContract` in `jwks_test.go` constructs cases by replacing YAML strings. | Use explicit inputs. Put the general duration syntax, units, minimum, zero, and error-path contract with loading tests in `config_test.go`; retain JWKS-specific limits in `jwks_test.go`. Preserve rejection of the old `jwks_uri` schema. |
| `TestLoadAppliesDefaults`, `TestAuthExampleAppliesAllDefaults`, and baseline checks in `TestListenerLimitsOnEveryChainAndFixedControls` repeat defaults. | Give default values one owner in `defaults_test.go`. Keep the listener test focused on overridden values reaching every chain and fixed request controls. Keep the loaded-vs-resolved timeout distinction. |
| `TestServerTLSDefaults`, `TestOptInOverloadDefaults`, and `TestKubernetesYAMLOptions` protect additional defaulting contracts. | Keep distinct cases for file-only TLS paths, Secret-derived paths, explicit paths, opt-in overload, omitted/null fields, explicit zero, and empty resource maps. Place default-only cases in `defaults_test.go`; keep resource-generation assertions in `kubernetes_test.go`. |
| `TestDefaultsDoNotMutateInput`, `TestAuthenticationDefaultsDoNotMutateInput`, `TestServerDefaultsDoNotMutateInput`, `TestKubernetesDefaultsCloneInputs`, and alias checks inside JWKS/timeout tests overlap. | Consolidate copy/default ownership checks in `defaults_test.go`, with named cases for distinct nested maps, slices, and pointers. Retain the route-reuse story in `TestResolvedRouteTimeoutsAndReuse`. Exercise public validation/generation paths for caller immutability where private-default checks alone are insufficient. |
| `TestLoadAuthExample` mainly checks fixture counts and claim-path lengths; root example generation is checked elsewhere. | Use one supported-example smoke table in `config_test.go` for `config.example.yaml`, `config.auth.example.yaml`, and `config.production.example.yaml`. Load each and exercise the supported generation/serialization path. Put behavior assertions in the dedicated suites. |
| `TestValidateRejectsInvalidConfiguration` and `TestValidateRejectsInvalidRouteConfiguration` often assert only that an error exists. | Keep core configuration and route constraints in `config_test.go`. Give each case its intended field/error. Build a valid baseline and change one relevant property. The invalid-regex case is correctly isolated: the fixture already uses a regex matcher. |
| `TestValidateServers` is separate from the server-focused tests. | Put server/binding validation together in `servers_test.go`. Retain required-server loading, hostname restrictions, unknown/repeated bindings, server-scoped route conflicts, and validation of unbound APIs. Combine identical constraints rather than repeating them across files. |
| The authentication validation cases "authorization without authentication" and "public server with authorization" make the same mutation. | Keep one case in `auth_test.go`, with the expected error. Review the remaining cases individually rather than deleting by similar names. |
| Literal claim keys, single-JWT `all_of`, `any_of` with unused attributes, duplicate issuers per server, and future mTLS schema rejection are distinct. | Retain these contracts in `auth_test.go`. Replace the mTLS YAML replacement with an explicit unsupported-schema document. |

For copy tests, mutate the returned copy and verify the original nested value
stays unchanged. Keep fresh input per case so one mutation cannot invalidate
another case. Do not replace meaningful nested checks with a superficial
top-level equality assertion.

### 5.2 Envoy generation and golden checks

| Current tests or finding | Required action and protected story |
| --- | --- |
| `TestGeneratedReferenceFiles` | Keep it in `generate_test.go`. Retain all eight fixture families: public routing, route lists, server TLS, plain JWT, direct JWT headers, mapped JWT headers, multiple issuers, and production tuning. Preserve the generated Envoy, processing, and Kubernetes references. |
| `TestGenerateBuildsNamedAPIClustersAndRoutes` includes basic defaults, cluster/route assertions, and repeat-generation checks. | Keep the added-API routing/cluster story. Remove baseline assertions already owned by defaults or goldens. Move determinism into the shared generation scenario table described below. |
| `TestGenerateAllowsMethodsOnOnePath`, `TestGenerateBuildsRoutesFromRouteLists`, `TestGenerateScopesAPIExposureToServers`, and `TestGenerateUsesAPIBindingOrder` | Retain distinct contracts: combined method fallbacks and `Allow`, exact/prefix/regex rewrites, server exposure/isolation, and API binding order. Do not replace these with counts alone. |
| `TestGenerateBuildsHTTPAndSNISelectedHTTPSChains` and file-only certificate checks | Retain HTTP/HTTPS chain selection, authority/SNI separation, and SDS file content/path behavior. Kubernetes goldens alone do not prove file-only generation. |
| `TestGenerateRejectsInvalidConfiguration` | Keep a focused public-generation rejection check. Reuse validation ownership for the constraint details instead of replaying the complete validation matrix through every entry point. |
| Filter order is checked by `TestGenerateIncludesAuthenticationAuthorizationAndProcessing`, `TestJWTFilterOrderAndNativeProviders`, `TestJWTProcessingAndHeaderFilterOrder`, and `TestJWTProcessingUsesFileBasedECDSConfiguration`. | Put exact conditional filter order in one table in `jwt_generate_test.go` for public, plain JWT, direct headers, and mapped headers. Move useful provider assertions to provider-focused coverage. Keep ECDS source/resource checks separate from order. |
| `TestGenerateJWKSProviderClusterCount` only checks a total. | Merge its useful contract into provider-focused tests that check provider identity, cluster association, endpoint/trust configuration, and used-provider selection. Remove the standalone count-only test. |
| `TestJWTAuthorizationReadsOriginalClaimsFromNamedProvider` and `TestJWTAuthorizationPolicyCombinationsAreAPIScoped` | Retain original-provider metadata and API-scoped grant composition. These protect authorization semantics that filter order alone does not establish. |
| `TestJWTRequiredHeadersAreRouteScopedAndManaged` | Retain route-selected headers, caller-value removal, required values, and local fallback behavior. Keep its purpose distinct from overall filter order. |
| `TestJWTExpressionsUseEnvoyCELVariablesAndGuardMissingAttributes` checks expression substrings and uses a production helper to build expectations. | Map each assertion to surviving golden and e2e coverage for missing claims, literal keys, escaped values, and passthrough. Remove or reduce the test only after this mapping is verified. Keep any unique contract with an independent expectation. |
| `assertNoLuaResources` repeats obsolete-implementation checks. | Prefer exact expected native filter chains and expected generated-file sets. Remove scattered negative string checks once those positive contracts cover the same protection. |
| Determinism checks occur in public generation, `TestJWTProcessingIsDeterministic`, and JWKS Kubernetes generation. | Use one scenario table in `generate_test.go` that compares complete generated file maps and serialized Kubernetes output. Include mapping maps with different insertion orders and scenarios with multiple CA mounts. Keep user-declared lists identical in equality comparisons; their ordering has separate behavior tests. |

Golden output is an independent regression check. Keep
`make update-golden` as the explicit update path and review every changed file.
Helper, constant, and receiver moves should normally produce no golden diff.
Investigate unexpected changes instead of accepting them by regeneration.

### 5.3 Kubernetes, trust, and production settings

| Current coverage | Required action and protected story |
| --- | --- |
| Metrics Service exposure, mixed HTTP/HTTPS ports, and HTTPS-only ports in `kubernetes_test.go` | Combine repeated port-map setup into one table. Retain each exposure mode, shared listener target, metrics port, and absence of an exposed admin port. |
| `TestGenerateKubernetesKeepsProcessingConfigOutsidePodTemplate` and `TestGenerateKubernetesOmitsProcessingConfigWithoutMappings` | Keep both conditional configurations. A mapping-only change must alter the processing resource while leaving the main ConfigMap and complete Pod template unchanged. Direct headers must not create processing resources. |
| Server TLS mounting, shared Secret/path mounting, and one Secret mounted at different paths | Retain separate mount-deduplication and projection stories. Check custom filenames, read-only directory mounts without `subPath`, separate SDS resources, and deterministic ConfigMap projection. Consolidate only repeated extraction code. |
| `TestValidateKubernetesTLSMounts` | Keep distinct invalid Secret/path combinations, reserved directories, and overlapping mounts in `servers_test.go`. Preserve valid shared-mount cases. |
| `TestGenerateKubernetesRequiresSettings` and `TestGenerateKubernetesFitsConfigMapNameLimit` | Retain public generator preconditions and name-length boundary behavior. Check the intended failure for missing settings. |
| `TestJWKSTransportAndTrust` and `TestJWKSValidationIncludesUnusedProviders` | Keep DNS/IP identities, system/custom CA trust, CA mount reuse, provider separation, timeout/circuit-breaker values, and validation of unused providers. Move shared determinism and copy checks to their assigned owners. |
| `TestUpstreamTLSAndExplicitProtocols` | Retain upstream trust, SNI/SAN behavior, and explicit HTTP/1 vs HTTP/2 generation. Shared TLS helpers do not make API-upstream and JWKS configuration contracts interchangeable. |
| `TestResolvedRouteTimeoutsAndReuse`, `TestListenerLimitsOnEveryChainAndFixedControls`, and `TestTuningValidationAndOptionalZeros` | Retain inheritance, explicit-zero semantics, per-chain limits, fixed control-header removal, and invalid effective-timeout combinations. Remove only repeated baseline-default assertions. |
| `TestOverloadGeneration`, `TestKubernetesValidationAndOverloadBudgets`, and `TestHeapBudgetComparedExactly` | Retain disabled/enabled overload behavior, monitor/action generation, resource validation, threshold ordering, and exact memory comparisons. Boundary cases above signed-integer range, at `MaxUint64`, and with fractional quantities protect different failures. |
| `TestMetricsAndConcurrencyGeneration` | Retain scrape timing, independent collector resources, explicit Envoy concurrency, and the absence of CPU-derived concurrency. |
| `TestKubernetesYAMLOptions` extracts YAML with `strings.Cut` and concatenates escaped fragments. | Use readable explicit inputs for omitted/null/empty cases. Keep these parser/default contracts even after their assertions move to `defaults_test.go`. |

### 5.4 E2e stories and framework boundaries

Similar assertions across conditional gateway configurations are not
automatically duplicates. Preserve these separate stories:

| Owner | Story and observable result |
| --- | --- |
| `e2e/http_test.go` | Route/method selection, local 404/405 with `Allow`, exact/prefix/regex rewrites, and backend method/path/header/body echo. The metrics story observes scraped Envoy metrics on the Service endpoint. |
| Plain JWT group in `e2e/jwt_test.go` | Valid credentials authorize without optional processing/header filters. Invalid credentials and denied original claims are rejected before upstream delivery. |
| Direct JWT headers group | Verified values replace spoofed managed headers. A caller-supplied header cannot fill a missing required attribute. |
| JWT access and identity processing group | Both issuers work over HTTP and HTTPS. Authorization uses original claims; the backend sees processed attributes and no bearer token. Preserve literal dotted keys, escaped values, missing/unsafe attributes, ordered mapping, passthrough, and server isolation. |
| Mapping reload scenario | Apply only the processing ConfigMap. Observe the new backend value with unchanged original-claim authorization and unchanged Pod UID. |
| JWKS lifecycle group | Keys rotate without a gateway restart, and a warm cache remains usable during one issuer's outage. Preserve the deliberate restart that creates a cold cache, healthy-issuer isolation, fail-closed behavior for the unavailable issuer, and recovery without another restart. |
| `e2e/tls_test.go` | SNI/authority isolation and bound APIs work. Certificate renewal changes the served certificate/key while the other server's certificate and gateway Pod UID stay unchanged. |
| `e2e/internal/framework/forward_test.go` | A ready Pod and named target port are selected correctly. Terminating Pods are excluded. These are separate infrastructure failure modes. |

Use httpbin to verify what reaches the backend. Denial cases must establish
that the response was rejected before backend handling, rather than merely
checking that some request failed.

Keep `Ordered` containers, use-case labels, separate namespaces, `BeforeAll`,
`DeferCleanup`, bounded polling, and parallel-safe diagnostics. Reuse setup only
where it does not hide a scenario or couple its mutable state to another group.

Do not add gateway e2e tests for Envoy timeout, retry, HTTP/2 flow control,
overload, or draining semantics. Configuration and generation tests own the
gateway's settings contract. Keep pinned-image validation available for runtime
configuration compatibility.

### 5.5 Test review exit conditions

- Every retained function and table case has a distinct behavior and a useful
  failure signal. Every removal names its surviving coverage or rationale.
- Repeated defaults, filter-order checks, determinism loops, fixture loading,
  and trivial assertions have one owner.
- Tests use fresh inputs and explicit YAML. No YAML is built through
  `strings.Replace` or `strings.ReplaceAll`.
- Negative tests assert the intended cause. Expected results do not simply
  recalculate the implementation's result with its own helper.
- Goldens and the distinct e2e/framework stories remain in place.
- New tests are limited to real behavior gaps found during the review. Do not
  replace deleted low-value tests with helper-only tests or a test-count target.

## 6. Documentation consolidation plan

### Findings

- `README.md` mixes configuration guidance, test internals, project rationale,
  and broad Envoy capabilities. Its "Why Envoy" section mentions features and
  support claims that are not established gateway capabilities.
- It does not show a complete minimal Go-library generation workflow. There is
  no gateway CLI to document as if one already existed.
- `docs/jwt-auth.md`, `docs/tls-secrets.md`, the README, and `AUTH-PLAN.md` repeat
  filter, mapping-update, TLS-update, and test explanations.
- The deleted `AUTH-PLAN.md` contained useful technical material mixed with implementation
  history and a stale instruction against golden comparisons.
- `config.mtls.example.yaml` still links to `AUTH-PLAN.md`. Replace that reference
  during the documentation cleanup.

### Source-to-destination map

| Existing content | Destination and action |
| --- | --- |
| README purpose, routing, servers, logging, and metrics | Rewrite for configuration authors in `README.md`. Keep implemented capabilities and user tasks. Remove promotional rationale and unsupported support/feature claims. |
| JWT schemas, plain JWT, direct headers, mappings, issuer selection, and failure behavior in `docs/jwt-auth.md` | Merge user instructions into `README.md`. Move metadata, CEL, native filter, cluster, and ECDS details into the new `docs/envoy.md`. |
| TLS Secret setup and renewal behavior in `docs/tls-secrets.md` | Merge user setup/update instructions into `README.md`. Move mount layout, SDS, watched-directory behavior, and useful references into `docs/envoy.md`. |
| Useful generation details in the deleted `AUTH-PLAN.md`, available at `8be60ba:AUTH-PLAN.md` | Merge into `docs/envoy.md`. Put current test commands and contributor rules in the new `CONTRIBUTING.md`. Discard implementation history and superseded instructions. |
| Test setup and rotation-test mechanics in README/JWT/TLS docs | Put contributor commands and test responsibilities in `CONTRIBUTING.md`. End-user docs describe the resulting behavior. |
| Root example YAML files | Keep supported examples consistent with the public schema and documented defaults. Retain the future mTLS example with an explicit unsupported status and a valid reference. |
| `HANDOVER.md` and this document | Keep as agent work/status documents, distinct from end-user instructions. Update status after implementation. |

Remove `docs/jwt-auth.md` and `docs/tls-secrets.md` only after their useful
content has a destination. Recover useful material from the already deleted
`AUTH-PLAN.md` through Git history. Update all live links and example comments
in the same documentation change.

### Required README contents

1. State what the gateway implements and link to the supported examples. Label
   mTLS authentication as future work.
2. Show one minimal, runnable Go example using
   `github.com/rhobs/auth-gateway/config`: read input, call `Load`, call
   `Generate` for file output or `GenerateKubernetes` and `YAML` for a manifest,
   handle errors, and write the output. Explain `Objects` where programmatic
   Kubernetes integration is useful. Do not invent a CLI or controller.
3. State prerequisites and deployment steps. Explain that referenced TLS
   Secrets and CA ConfigMaps must exist in the target namespace. Separate
   generation requirements from Kubernetes deployment and e2e prerequisites.
4. Explain host/API bindings, route and method order, match/rewrite options,
   upstream protocols/trust, and 404/405 behavior with a small working example.
5. Explain plain JWT authorization, direct header output, and ordered mappings
   as three configuration choices. Distinguish original claims from processed
   attributes. Describe managed headers, issuer scoping, and failure behavior.
6. Describe duration syntax, omitted/null/explicit-zero behavior, inheritance,
   resource overrides, overload opt-in, metrics timing, and explicit worker
   count. Use compact setting tables and supported examples instead of repeated
   prose about each default.
7. Give deployment/update instructions with this explicit contract:

   | Change | Required action and effect |
   | --- | --- |
   | Values in existing mapping tables | Update the processing ConfigMap. ECDS reloads the mappings without a Pod restart. |
   | Downstream certificate/key in a mounted TLS Secret | Update the Secret. SDS reloads it for new TLS connections. |
   | Routes, providers, other static configuration, or deployment settings | Regenerate and apply resources. Roll out the gateway as required for static configuration. |
   | Upstream/JWKS CA bundle | Update the bundle and explicitly roll out the gateway. |

8. Explain error access logs, the metrics endpoint, internal admin binding, and
   common configuration/authentication/authorization failures. Link to the
   technical document and contributor guide for their respective audiences.

### Required `docs/envoy.md` contents

- The `Load`/validation/resolution/generation flow and resource outputs.
- Shared listener, virtual host, SNI/authority, route ordering, rewrites, and
  method fallbacks.
- Conditional native filter order: request controls, JWT verification,
  original-claim RBAC, optional working attributes/mappings, required-header
  checks, header mutation, and router.
- Provider metadata vs working attributes, literal claim keys, processor
  ordering, bytes/string constraints in Envoy 1.39.1, and passthrough behavior.
- Upstream/JWKS trust and identities, independent provider clusters/caches, and
  the limits of cache TTL during outages and rotation.
- ConfigMap, Secret, and CA packaging; file-only output; mount deduplication;
  SDS/ECDS watched-directory behavior; and why static changes require rollout.
- Fixed request controls, timeout resolution, explicit protocols, overload
  resources, logging, and collector integration.

Use one concise flow or sequence diagram when it clarifies these relationships.
Link to the README for user procedures instead of repeating them.

### Required `CONTRIBUTING.md` contents

- Go/tool requirements and the local commands in section 8.
- The same-file receiver rule, consolidated layout, constant ownership, and
  expectations for concise code comments.
- Test ownership, meaningful scenarios, explicit YAML, fresh inputs, and
  independent expectations.
- Golden update/review instructions and the difference between unit,
  compilation, runtime-image, and live e2e checks.
- Kind prerequisites, scenario labels, namespace isolation, cleanup, and
  diagnostics locations.

### STE and documentation exit conditions

Use short sentences, active voice, direct instructions, consistent terms, and
ASCII punctuation. Define technical abbreviations at first use. Keep one
instruction per step. Remove filler, project history, speculative capabilities,
and repeated explanations. Reserve internal implementation detail for readers
who need it.

Exit condition: a configuration author can follow the generation and deployment
instructions without reading an agent plan. The Go example and supported YAML
examples work, relative links resolve, and the reload/rollout instructions match
the implementation. Each topic has one main documentation home.

## 7. Reviewable work units

Use the existing feature branch. Suitable implementation units are:

1. Validate and finish the receiver moves and tagged compilation fix.
2. Simplify helpers/defaulting, consolidate constants, and finish local linting.
3. Consolidate tests and fixture setup with a recorded surviving-coverage map.
4. Merge and rewrite end-user/technical/contributor documentation.
5. Run final validation and record results and remaining limitations.

Keep each unit focused and use concise natural-language commit messages. Do
not push directly to `main`. Any published changes go through review.

## 8. Verification and completion

Run targeted checks after meaningful changes, then the full checks before
implementation handoff. Once a check passes, repeat it when subsequent changes
affect what it validates.

| Check | Purpose |
| --- | --- |
| `make test` | Unit behavior and golden regressions. |
| `make lint` | Formatting, configured static checks, repeated strings, and duplicate code across production and tagged tests. |
| `go test -tags=e2e,envoyruntime -run '^$' ./...` | Compile all tagged suites without claiming live execution. |
| `go test -tags=e2e ./e2e/internal/framework` | Framework behavior, including Pod and port selection. |
| `make -C e2e test GINKGO_ARGS='--label-filter=jwt'` | Focused live JWT development check when JWT generation/setup changes. |
| `make e2e` | Complete existing Kind suite before implementation handoff. |
| `make test-runtime` | Optional generated-configuration validation with pinned Envoy/collector images; useful when generation compatibility is uncertain. |
| `git diff --check` | Whitespace and patch hygiene. |

`make update-golden` is an explicit maintenance action, not a substitute for
passing the tests. Review the resulting diff, then rerun normal tests.

The Kind suite needs Docker, Kind, Go, curl, and network access. It downloads
cmctl on first use, creates or reuses the local cluster, and uses two Ginkgo
processes by default. Reports are written under `e2e/.state/reports`; scenario
diagnostics use the framework's context-specific state directory. If the
default Go cache is restricted, the earlier work used
`GOCACHE=/private/tmp/auth-gateway-go-cache`.

Also inspect the final receiver/type placement, all public API/YAML changes,
remaining YAML string construction, documentation links, supported examples,
and generated resource changes. Run the documented Go example during the
documentation phase.

The implementation is complete when:

- All code, test, fixture, example, build-tool, and documentation areas in this
  plan have been reviewed; deliberate no-change decisions are recorded.
- Receiver ownership, constants, and local linting meet the stated rules.
- Tests protect distinct stories, removed tests have a coverage rationale, and
  golden/runtime behavior remains stable.
- The README, Envoy document, and contributor guide serve their stated
  audiences. Superseded docs and broken links are removed.
- Required checks have actual recorded results. Any unavailable live check is
  listed as pending with its reason, not reported as passed.
- This plan and `HANDOVER.md` record completed work, surviving-test decisions,
  actual check results, pending work, and separate API recommendations.

The original planning snapshot in Section 2 is historical. The completed
implementation, test consolidation decisions, and actual verification results
follow.

## 9. Completed implementation record

Updated: 2026-10-03.

Implementation is complete on branch `code-quality-cleanup`. The code and test
cleanup is committed as `409b346` (`Refactor config and e2e test code`); the
documentation and runnable example are committed as `96bcc20`
(`Document gateway generation and operations`). No public Go signatures, YAML
fields, defaults, generated resource names, or runtime behavior were
intentionally changed. No API recommendations were identified during this
cleanup.

### Final test coverage inventory

| Owner | Scenario | Expected result |
| --- | --- | --- |
| `config/config_test.go` | Strict one-document YAML loading, duration parsing, root and route validation, supported examples, listener limits, timeout inheritance/reuse, and upstream TLS/protocol settings. | Valid inputs load and generate; invalid inputs report the intended field; resolved settings preserve override order and caller input. |
| `config/defaults_test.go` | Auth example defaults, opt-in overload thresholds, file/Secret TLS paths, nested maps/slices/pointers, public operations, and omitted/null/empty Kubernetes options. | Defaults match the documented values; explicit empty resource maps stay empty; defaulting, validation, and generation do not mutate caller-owned data. |
| `config/servers_test.go` | Required servers, exact hostnames, API bindings, server-scoped route conflicts, unbound API validation, and TLS mount paths. | Invalid binding or mount combinations fail with the relevant field; valid HTTP/HTTPS and shared-mount cases remain valid. |
| `config/auth_test.go` | Supported auth example shape, literal claim keys, JWT `all_of`, unsupported mTLS schema, authentication/policy validation, optional attributes, and per-server issuer uniqueness. | Original claim paths and grant values remain exact; unsupported or inconsistent auth reports the relevant field; issuers stay server-scoped. |
| `config/jwks_test.go` | Null defaults, legacy `jwks_uri` rejection, endpoint identity and CA trust, provider separation, and validation of unused providers. | Each provider keeps its own trusted cluster; DNS/IP identity checks and schema errors remain explicit. |
| `config/generate_test.go` | Eight complete reference families, named API clusters, routing/method fallbacks, rewrites, HTTPS/SNI selection, server API scope/order, and deterministic generation. | Generated files match reviewed references; local 404/405 behavior, `Allow`, order, and map-order stability are preserved. |
| `config/jwt_generate_test.go` | Provider identity, original-claim authorization, public/plain/direct/mapped filter order, route-required headers, ECDS output, CEL claim guards, and API-scoped policy combinations. | Only required native filters/resources appear; authorization uses the named provider's original claims; missing required headers fail before forwarding. |
| `config/kubernetes_test.go` | Processing ConfigMap isolation, conditional processing resources, Service/metrics ports, TLS Secret mount reuse/projection, generator preconditions, overload budgets, resource quantities, and Envoy worker count. | Mapping changes leave bootstrap and Pod template unchanged; TLS projection and service exposure remain correct; invalid capacity settings fail at their boundaries. |
| `config/runtime_test.go` | Optional validation of generated files with the pinned Envoy and collector images. | Runtime parsers accept the generated resources. This check was not run separately; the full live e2e suite used the pinned Envoy image. |
| `e2e/internal/framework/forward_test.go` | Ready-Pod selection, named target-port resolution, and exclusion of terminating Pods. | Port forwarding selects only a ready, non-terminating target and the requested service port. |
| `e2e` Ginkgo suite | HTTP routing and metrics; plain JWT; direct headers; original-claim authorization; processed headers; issuer isolation; mapping reload; JWKS rotation/outage recovery; TLS host isolation and renewal. | HTTP responses and httpbin observations prove forwarding, denial, and update behavior; mapping and certificate reloads preserve the Pod identity. |

### Test consolidation and removal map

| Consolidated or removed check | Surviving coverage and reason |
| --- | --- |
| `TestLoadAuthExample`, `TestLoadAppliesDefaults`, and `TestRootExampleGeneratesKubernetes` | `TestAuthExampleContainsExpectedJWTConfiguration`, `TestAuthExampleAppliesAllDefaults`, and `TestSupportedExamplesGenerate` own example shape, defaults, and generation. The supported-example test now covers all three supported root examples. |
| `TestDefaultsDoNotMutateInput`, `TestAuthenticationDefaultsDoNotMutateInput`, `TestServerDefaultsDoNotMutateInput`, and `TestKubernetesDefaultsCloneInputs` | `TestDefaultsCloneInputs` keeps named cases for route, auth, JWKS, server, and resource ownership. `TestPublicOperationsPreserveConfiguration` covers `Validate`, `Generate`, `GenerateKubernetes`, and YAML serialization through the public path. |
| Duplicate `public server with authorization` validation case | Removed because it made the same mutation and asserted the same error as `authorization without authentication`. The latter remains in `TestValidateRejectsInvalidAuthenticationAndAuthorization`. |
| `TestGenerateIncludesAuthenticationAuthorizationAndProcessing` and `TestJWTProcessingAndHeaderFilterOrder` | `TestConditionalJWTFilterOrder` checks exact order for public, plain JWT, direct-header, and mapped-header cases. Provider, ECDS, and required-header behavior remains in focused tests. |
| Count-only `TestGenerateJWKSProviderClusterCount` | The provider test checks provider names and cluster associations, endpoint trust, selection, and the related count. The standalone total-only assertion added no distinct contract. |
| `TestJWTProcessingIsDeterministic` and repeated same-input determinism loops | `TestGenerationIsDeterministic` compares complete generated file maps and Kubernetes manifests across distinct mapping/resource map insertion orders and multiple CA mounts. |
| `assertNoLuaResources` helper and negative Lua-name scans | Exact conditional filter chains and expected generated-file lists positively assert the supported native filter output and exclude obsolete resources from those cases. |
| `TestKubernetesDefaultsCloneInputs` and its string-built `TestKubernetesYAMLOptions` cases | `defaults_test.go` owns the copy/default contract. Explicit fixtures cover omitted, null, empty, nested-null, and empty-resource-map semantics; Kubernetes generation tests keep the output behavior. |
| `TestServerTLSDefaults`, `TestValidateServers`, and `TestValidateRejectsInvalidUnboundAPI` locations | These checks were moved to the owning `defaults_test.go` or `servers_test.go`; their distinct defaulting and validation behavior remains covered. |
| General `TestDurationYAMLContract` location in `jwks_test.go` | The general duration syntax and field-path cases now live in `config_test.go`; JWKS-specific null defaults, limits, and legacy schema rejection stay in `jwks_test.go`. |
| YAML replacement in mTLS and JWKS tests; validation tests that accepted any error | Unsupported-schema and JWKS cases now use explicit input or fixtures. Validation tables assert the intended field or error text instead of accepting an unrelated failure. |

### Verification results

| Check | Result |
| --- | --- |
| `make test` | Passed, including compilation of `examples/generate-kubernetes`. |
| Cached golangci-lint `v2.14.0` with `./...` | Passed with `0 issues`; the configured `e2e` and `envoyruntime` build tags were active. |
| `make lint` | The formatting check passed, but its pinned `go run` could not download the tool because DNS resolution for `proxy.golang.org` is unavailable. The cached binary of the same version passed as above. |
| `go test -tags=e2e,envoyruntime -run '^$' ./...` | Passed; all tagged packages compiled without executing live e2e tests. |
| `go test -tags=e2e ./e2e/internal/framework` | Passed. |
| `make e2e` | Passed: 21 specs, 21 passed, 0 failed, 0 pending, 0 skipped. It ran against the pinned Envoy image in the local Kind cluster. |
| Documented Go example | Passed: `go run ./examples/generate-kubernetes config.example.yaml auth-gateway.yaml` generated a Kubernetes manifest; the temporary output file was removed after inspection. |
| Local documentation links and ASCII check | Passed for `README.md`, `CONTRIBUTING.md`, and `docs/envoy.md`. |
| `gofmt -l config e2e examples` and `git diff --check` | Passed with no formatting or whitespace findings. |
| `make test-runtime` | Not run separately; it is optional, and the complete e2e suite ran against the pinned Envoy image. |

The `make lint` limitation is environmental: the standard target uses the
version-pinned Go module command and the module proxy is unreachable here. No
lint findings remain. The complete live suite ran successfully, so there are no
pending required checks.
