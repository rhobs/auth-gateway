# Test suite coverage and runtime plan

Review date: 2026-10-11. Reviewed commit: `82fc309`.
This plan complements the [production readiness review](production-readiness-review.md).
It is a worklist: each numbered item is small enough for an agent to take on a
feature branch. Do not push or open a PR until asked.
The timing tables are the pre-change baseline. Implementation status and
remaining validation are recorded in the phases below.

## Goal and test boundary

Cover every supported configuration option at the cheapest layer that can prove
its contract. Unit tests should cover schema, defaults, invalid combinations,
generated filter order, and generated resources. Live tests should prove the
observable interaction of authentication, authorization, processing, routing,
and the Envoy reload behavior this gateway depends on.

Testing every Cartesian combination in Kind would grow without bound. Use a
complete decision table for the small authentication and authorization state
machines, pairwise coverage for compatible options, and targeted three-way
cases where a security boundary crosses authentication, authorization, and
processing. Record invalid combinations as such. A live acceptance case must
check what reached httpbin, including method, path, headers, and body; a denied
case must show that the upstream request count did not change.

The supported schema is [the configuration reference](configuration-reference.md).
mTLS is future work. Keep generic Envoy flow control, timeout, retry, overload,
and connection-draining semantics out of gateway e2e tests, as required by
`AGENTS.md`. File watching, SDS, ECDS, and the rollout boundary are in scope
because the gateway's documented behavior depends on them. JWKS cache settings
belong in generated-output unit tests; warm and cold cache behavior is Envoy's
contract, not a gateway e2e contract.

## Measured baseline

Three passing Ginkgo reports from 2026-10-11 each ran 63 of 63 specs with two
workers. Their runtimes were **13m24.7s**, **12m9.7s**, and **12m2.6s**: a
**12m9.7s median**, with a **12m2.6s-13m24.7s range**. The reports are
`e2e/.state/reports/r20261011fabc/auth-gateway.json`,
`e2e/.state/reports/rbee18c58dc760bbd/auth-gateway.json`, and
`e2e/.state/reports/rkindtool3/auth-gateway.json` (local, ignored by Git).
These are warm-cluster Ginkgo report times. They exclude `make e2e` tool setup,
Docker pulls, image loads, framework tests, and compilation.

Ginkgo charges one-time setup to the first spec in an `Ordered` container and
deferred cleanup to the last. The times below are inclusive, not pure request or
reload latency. In particular, a long last spec can include namespace deletion.
Parallel workers can hide some work, so a spec's inclusive time is not an
estimate of wall time saved by removing it.

| Ordered container | Specs | Median | Range |
| --- | ---: | ---: | ---: |
| API-key authentication | 9 | 552.9s | 538.7-565.5s |
| Replicas and bootstrap rollouts | 3 | 274.8s | 263.2-277.7s |
| JWT access and identity processing | 13 | 110.0s | 98.0-112.9s |
| Server TLS | 3 | 105.5s | 42.0-115.7s |
| HTTP routing and metrics | 17 | 61.0s | 58.6-68.7s |
| Tracing | 1 | 59.4s | 48.9-61.0s |
| JWT JWKS lifecycle | 1 | 55.3s | 53.3-57.7s |
| Plain JWT authorization | 3 | 39.3s | 39.2-40.2s |
| Header-sourced attributes | 5 | 33.7s | 32.5-115.2s |
| Multi-replica server TLS | 1 | 32.3s | 31.8-42.3s |
| Direct JWT headers | 4 | 31.3s | 30.4-31.5s |
| Upstream TLS and HTTP/2 | 2 | 31.2s | 29.1-32.2s |
| API-key namespace isolation | 1 | 29.2s | 29.1-30.2s |

The historical API-key group had nine specs. Its first gateway setup took a
median 3.54s, while deleting its namespace took 27.01s. Request-only specs were
under one second each; Secret and mapping restore hooks added most of the long
per-spec time. The current layout combines read-only credential and selector
cases on one fresh gateway, keeps projected Secret rotation in its own
namespace, and keeps namespace isolation separate. The runtime suite owns
malformed ECDS retention, recovery, and empty-key revocation. The first reduced
run measured the projected Secret spec at 31.4s, down from 4m44.3s for the
former API-key lifecycle. See Phase 3.1 for full-suite timings; repeat the run
before treating this reduction as stable.

The API-key container's elapsed time was 70%, 74%, and 77% of the three
report runtimes.
With the present `Ordered` groups, adding workers cannot shorten the suite
below its longest group: a 9m13s median, with an 8m59s-9m26s range, even
with perfect scheduling and no contention. Optimize that group before adding
workers. The wide ranges in the header and TLS groups call for per-step
timings before claiming savings.

## Coverage inventory

| Contract | Current evidence | Gap or next check |
| --- | --- | --- |
| Public, JWT-only, key-only, two-JWT `any_of`, mixed JWT/key `any_of` and `all_of`, and two-JWT-plus-key `any_of` | Routing, JWT, API-key, and header-source containers | No remaining decision-shape gap. Keep the ledger current when authenticators change. |
| Missing, invalid, expired, wrong-issuer, wrong-audience, and future-`nbf` JWT; audience omitted; list claim grants | [JWT scenarios](../e2e/jwt_test.go) | No remaining request gap. |
| Missing, unknown, denied, rotated, malformed-update retention, recovery, and empty API-key resource; default and custom headers | [API-key scenarios](../e2e/api_keys_test.go) and [file-based runtime test](../config/runtime_live_test.go) | Kind checks one projected Secret rotation. The runtime test checks malformed-update rejection and retention, recovery, and empty-key revocation. |
| Policy `any_of` and `all_of`, grant attributes, API scoping, issuer isolation, raw values unaffected by mapping | JWT and API-key scenarios | No remaining request gap. The no-policy and policy-veto cases use valid authentication. |
| Claim, credential, and source-header attributes; one and two ordered mappers; unmatched pass-through; managed output headers; missing and unsafe required output | JWT, API-key, and header-source scenarios | Null, empty, number, and list values are checked on a required output route. Processing ECDS rejection and recovery are covered. |
| Exact, prefix, and regex paths and rewrites; method fallback; API binding order; HTTP and SNI-selected HTTPS | [routing](../e2e/http_test.go) and [TLS](../e2e/tls_test.go) scenarios | The no-rewrite route checks the original path, query, headers, and body. Method-name validation remains a unit concern. |
| SDS server-certificate updates, ECDS API-key and mapping updates, two-replica fan-out, bootstrap rollout | TLS, API-key, JWT, and replica scenarios; [file-based runtime test](../config/runtime_live_test.go) | The full suite passed 64/64 with no skips, and `make test-runtime` passed on 2026-10-11. Repeat full runs after changes to establish stable timing. |
| JWKS cache duration and remote provider generation | [Default tests](../config/config_test.go), [generated-output tests](../config/kubernetes_test.go), and golden files | Cache duration is unit-only; no gateway e2e cache lifecycle remains. |
| Upstream TLS identity and CA, HTTP/2 selection, metrics, logs, tracing | Upstream, metrics, JWT log, and tracing scenarios | CA updates are checked across the rollout boundary. Keep numeric tuning and collector scrape settings in generated-output tests. |
| Kubernetes image/resource/port/concurrency options | [Schema ledger](schema-test-ledger.md), generated-resource tests, live custom ports, and two replicas | No field-ledger gap remains. Most resource values need generated-output assertions, not extra Pods. |

The [runtime image test](../config/runtime_test.go) validates generated files
against pinned Envoy and collector images. The tagged
[file-based runtime test](../config/runtime_live_test.go) starts Envoy and
httpbin, sends requests, and logs update-to-observed times for processing ECDS,
API-key ECDS, and TLS SDS. It does not start Kubernetes. The unit/golden suite
and live request suites have different contracts even when both mention the
same option.

### Security decision combinations

The distinct selector shapes can be enumerated in generated-output tests:
public; one JWT or one key under either selector; two JWTs under `any_of`;
JWT plus key under `any_of` or `all_of`; and two JWTs plus a key under
`any_of` as the higher-cardinality case. Cross each protected mode with
no policy, one policy under either selector, and multiple policies under
`any_of` or `all_of`. Mark invalid cells explicitly: a public server cannot
select policies, `all_of` cannot select two JWTs, JWT issuers selected on one
server must differ, and a configuration supports only one key authenticator.
The live suite should prove these distinct request decisions:

| Decision | Current evidence | Remaining check |
| --- | --- | --- |
| Public request reaches its bound API without credentials | Routing and API-key public hosts | None. |
| One JWT or one key accepts a valid credential, rejects a bad one, and applies an API grant | JWT and API-key hosts | None. |
| Two JWTs under `any_of` accept either selected issuer and isolate unselected issuers | JWT hosts | None. |
| Mixed `any_of` chooses the verified JWT first, falls back to the key, and denies when neither is valid | API-key and header-source hosts | None. |
| Two JWTs plus a key under mixed `any_of` accept either issuer or the key without accepting a spoofed issuer | Three-credential API-key selector | None. |
| Mixed `all_of` needs both credentials and equal nonempty raw attributes | API-key and header-source HTTPS hosts | None. |
| Valid authentication with no policy remains denied | Plain JWT authorization | None. |
| Multiple policies under `any_of` allow one grant; under `all_of` both must grant | Plain JWT authorization uses valid authentication to isolate the policy decision | None. |

Cross those decisions with claim, credential, and request-header sources,
zero, one, and two ordered mappers, and HTTP/HTTPS in a pairwise ledger. Add
targeted three-way cases where source selection or mapping could change a
grant. This keeps the live suite comprehensive at security boundaries without
repeating every independent routing and transport combination.

## Overlap and cost candidates

Times below are medians and ranges across the three passing runs.

| Candidate | Evidence | Recommendation |
| --- | --- | --- |
| Two direct Secret rotations on two replicas | The removed standalone SDS spec measured 32.3s (31.8-42.3s); the first [rollout](../e2e/replicas_rollout_test.go) spec measured 70.5s (69.5-71.7s) including setup. Both asserted changed certificate serials and stable Pod UIDs. | One rollout spec now owns the protected request, custom Service ports, certificate rotation, malformed Secret retention, recovery, and stable Pod UIDs on both replicas. Keep the cert-manager renewal test because it checks a distinct producer and SNI chain isolation. |
| Repeated ECDS reloads | The pre-change run measured four projected processing ConfigMap reloads: JWT 101.6s, API key 156.5s, header 29.1s, and two replicas 87.8s. | API-key credentials use one projected Secret lifecycle. The runtime test covers file-based processing and API-key ECDS updates; JWT and header requests retain their source-specific mapping checks, and the replica suite checks fan-out. Do not restore the duplicate API-key mapping reload. |
| JWKS cache lifecycle | The removed [JWT lifecycle scenario](../e2e/jwt_test.go) measured 55.3s (53.3-57.7s) and checked a warm cache during outage, cold-cache failure after restart, and fetch recovery. These are Envoy cache semantics. | Keep the default and override duration assertions in unit tests. Ordinary JWT request e2e coverage checks gateway-to-JWKS wiring. |
| API-key reset around every spec | The pre-change [API-key suite](../e2e/api_keys_test.go) reapplied the processing ConfigMap and key Secret before and after nine specs. Historical reset hooks added 65-90s to mutable specs. | Read-only decisions share one fresh gateway. Kind retains one projected Secret rotation; the runtime test covers malformed ECDS retention, recovery, and empty-key revocation. Keep namespace isolation in a separate group. |
| Similar JWT denials and HTTP/HTTPS route checks | Most individual request specs take less than 0.1s. They exercise different filter chains, Host/SNI selection, or upstream isolation. | Keep them unless their assertions are identical. Removing them will not materially shorten the suite. |
| Fixed wait in bootstrap rollout | [rollout test](../e2e/replicas_rollout_test.go) sends requests for 60 seconds after a bootstrap ConfigMap edit; the interval now has a timing marker. | Keep the observation until a full run confirms the projection evidence and shows whether a shorter bounded check preserves the rollout contract. |

## Phased worklist

Phases are ordered by dependencies. Independent items within a phase can be
assigned to separate agents. Each agent should keep checks local and report the
before/after spec count, coverage contract, and measured runtime.

### Phase 0: make cost and coverage visible

#### 0.1 Record repeatable timings (implemented)

Add a small report summarizer for Ginkgo JSON under `scripts/` and document its
command in [CONTRIBUTING.md](../CONTRIBUTING.md). Report `make e2e` setup,
compilation, and Ginkgo wall time separately. Within mutable specs, record
namespace setup, resource apply, apply-to-observed reload, assertions, reset,
and cleanup. Keep reports as CI artifacts. Use three warm runs for median and
range; time one cold run separately.

Done when: a report names every spec and container, first/last hook cost is
visible, and a future change can compare warm-run medians without reading raw
JSON by hand.

#### 0.2 Maintain a schema-to-test ledger (implemented)

For every field in [the configuration reference](configuration-reference.md),
record its unit validation/default test, generated-output test, and any needed
live request test. Enumerate valid authentication selector, authorization
selector, attribute source, mapping, and transport combinations. Mark invalid
ones with the validation rule. Add typed, table-driven unit generation tests
for valid combinations missing coverage; use valid baselines and change one
field for invalid cases. Mark JWKS cache duration as unit-only coverage.
The [schema-to-test ledger](schema-test-ledger.md) records field evidence and
the security decision matrix.

Done when: no supported field is unaccounted for, and each security decision
has a distinct expected `200`, `401`, or `403` and upstream-delivery outcome.

#### 0.3 Make Go test tools reproducible (implemented)

The root [Makefile](../Makefile) offers `make tools` for the pinned Ginkgo,
golangci-lint, Kind, and cmctl commands. The [e2e Makefile](../e2e/Makefile)
invokes Kind and cmctl through `go tool`; CI uses the same path instead of a
separate Kind download. Docker and Go remain external prerequisites.

Done when: a clean Go module cache fetches the pinned Kind, cmctl, Ginkgo, and
lint versions through `go tool` from Makefile targets, and CI no longer has a
separate Kind download recipe.

#### 0.4 Remove the JWKS cache lifecycle scenario (implemented)

Confirm that unit tests assert both the default JWKS cache duration and an
explicit override in generated Envoy configuration. The existing live
53-58s scenario tests warm-cache outage masking, cold-cache failure after a
restart, and fetch recovery. Remove it; ordinary JWT e2e requests already
prove the gateway can use its configured JWKS endpoint for authentication.

Done when: generated-output tests cover the configured cache value and no
gateway e2e scenario waits for or asserts JWKS cache behavior.

### Phase 1: close cheap gateway behavior gaps (implemented; full Kind validation passed)

#### 1.1 Complete the security decision table (implemented)

Use the existing JWT/API-key stacks. Add a future-`nbf` JWT case, a protected
server with no selected authorization policy, and two policies that can
disagree on the same already-authenticated request. Prove `any_of` permits one
grant while `all_of` requires both, with the losing request absent from
httpbin. Keep mixed JWT/key precedence, mismatch, and spoof checks as they are.

Done when: each new case distinguishes authentication failure from
authorization denial and checks the upstream counter. No new stack is needed.

#### 1.2 Cover working-value and route edges (implemented)

Add a small table in the current JWT processing stack for null, empty,
numeric, and list values used by a required output header. Each should deny
before the backend while an unrelated optional attribute can remain unset.
Add a public no-rewrite route to the routing fixture and assert its original
method, path, query, headers, and body at httpbin.

Done when: every documented working-value class has a live outcome and the
no-rewrite route has a full backend echo assertion.

#### 1.3 Cover multi-issuer key fallback (implemented)

Use a server selecting two distinct JWT issuers and one API key under
`any_of`. Exercise each valid credential separately, an invalid JWT with a
valid key, an unselected issuer, and a spoofed verification marker. Assert
the selected identity, grant, mapped output, and upstream delivery for each
accepted request; denied requests must not reach the backend. Pair this with
a generated-output check for each selected issuer and the key fallback.

Done when: the three-credential selector has an observable live decision for
every branch, with denied requests absent from the backend.

### Phase 2: test the Envoy file lifecycle we rely on (implementation complete; Kind and runtime validation passed)

#### 2.1 Add a fast file-based runtime harness (implemented)

Build on [the runtime image test](../config/runtime_test.go): write generated
file-based configuration at its declared paths, start the pinned Envoy image, and
send real requests. Update processing ECDS, API-key ECDS, and server TLS SDS
files by atomic replacement. Phase 2.2 separately checks Kubernetes projected
volumes. For each update, assert the new observable result without replacing
Envoy; send a malformed
update and assert the last accepted behavior or a documented fail-closed
result, then recover with a valid update. Keep these as runtime integration
tests that do not start Kind.

Done when: each file watcher and rejection/recovery path has a real Envoy
request assertion, with elapsed update-to-observed time recorded.

Validation passed on 2026-10-11 with `make test-runtime`, including the pinned
image checks. The live test observed valid ECDS and SDS updates within 3-4ms
after atomic replacement. Malformed processing, API-key, and TLS resources
increased Envoy update-failure counters, and the last accepted behavior held
through the two-second retention checks before valid recovery.

#### 2.2 Keep Kubernetes projection checks per resource (implemented)

Retain one projected Secret rotation check for API keys and one for server
certificates, one processing ConfigMap reload that preserves the Pod, and the
two-replica fan-out check. The Kind mapping case proves a projected ConfigMap
update reaches Envoy without replacing the Pod. The runtime test owns malformed
processing, API-key, and TLS file rejection and retention, valid recovery, and
empty-key revocation. Keep JWKS cache configuration assertions in unit tests
as described in Phase 0.

Done when: projected files, Envoy watchers, and two-replica distribution are
all covered without repeating each source-type mapping update in Kind.

#### 2.3 Confirm rollout-only inputs (implemented)

Use one representative CA bundle update to verify the documented trust
behavior: a mounted CA change alone does not activate a static cluster
configuration, while an explicit rollout does. Keep the existing bootstrap
metric-binding rollout check. Test collector ConfigMap changes at the
generated-resource level first; add a live test only if the promised reload
behavior cannot be established there.

Done when: docs and tests agree on which files hot reload and which require a
Deployment or collector rollout.

### Phase 3: remove avoidable serial work (implementation complete; first speed comparison recorded)

#### 3.1 Narrow API-key resets (implemented)

In [api_keys_test.go](../e2e/api_keys_test.go), read-only credential and
selector cases share one fresh gateway. A separate namespace verifies one
projected Secret rotation and stable Pod identity. The file-based runtime test
owns malformed-update retention, recovery, and empty-key revocation, avoiding
repeated projected Secret updates in Kind. Namespace cleanup isolates focused
runs and failures.

The tagged package compiles and an API-key Ginkgo dry run selects all eight API
key specs. The first post-change full attempt used two workers and selected 64
specs. It took 9m32s, with 33 passing, 4 failing, and 27 skipped, so it is not
a coverage-complete runtime measurement. Its local report is
`e2e/.state/reports/r9b9b8e79baec024b/auth-gateway.json`.

That attempt exposed four failures. The no-rewrite case used an httpbin path
that returns 404, so it now uses `/anything/no-rewrite`. Envoy returns 401 for
null, numeric, and list values used by a required JWT output, so the test now
expects the observed authentication result. Deployment readiness now waits for
the exact desired replica count, and Pod helpers ignore terminating Pods. The
replica TLS test had waited on xDS failure counters that do not increment for
filesystem SDS updates; malformed TLS retention and recovery stay in the
runtime test, while Kind checks certificate rotation across both replicas.
The 27 skips were Ginkgo's ordered-group cascade after those failures, not
intentional skips.

After those fixes, the full two-worker run selected and passed all 64 specs,
with zero failures and zero skips. Ginkgo took 10m50.6s; the run is recorded in
`e2e/.state/reports/rrelfull1/auth-gateway.json`. The timing sidecar reports
15.9s for image defaults, cmctl, and cluster/image setup, 0.6s for framework
tests, 4.5s for e2e compilation, and 10m51.9s for the Ginkgo command. This is
the first valid post-change sample, not yet a stability or speed benchmark.
The API-key lifecycle spec took 4m44.3s, JWT processing 4m00.8s, and replica
rollouts 4m56.4s. In the API-key spec, invalid-update rejection took 73.4s,
recovery 88.7s, and empty-Secret revocation 88.6s. These projected resource
waits motivate keeping the Kind check to one valid rotation while the runtime
suite proves ECDS rejection, retention, recovery, and revocation.

The next full run on the speed branch, `rrelsp3`, also selected and passed all
64 specs with zero failures and skips. Its report records 8m17.6s of Ginkgo
suite wall time, 2m33.0s less than `rrelfull1`. The API-key Secret projection
spec took 31.4s, 4m12.9s less than the former API-key lifecycle spec; both
inclusive spec times include namespace cleanup. The timing sidecar reports
19.5s for image defaults, cmctl, and Kind/image setup, 20.3s for framework
tests, 5.1s for e2e compilation, and 8m20.2s for the Ginkgo command. This is
one speed sample; repeat the two-worker run before treating the reduction as
stable. The report and timing sidecar are
`e2e/.state/reports/rrelsp3/auth-gateway.json` and
`e2e/.state/reports/rrelsp3/timings.json` (local, ignored by Git).

#### 3.2 Consolidate repeated SDS and ECDS waits (implemented)

The duplicate two-replica SDS spec is removed; its custom-port and protected
request assertions are in the rollout suite. The fast file harness covers
processing ECDS, API-key ECDS, and TLS SDS. Kubernetes tests retain key Secret,
certificate Secret, processing ConfigMap, and two-replica projection coverage.
The cert-manager renewal and static bootstrap rollout checks remain.

The JWT mapping spec remains a measured follow-up. In `rrelsp3` it took
4m21.4s, including 1m13.5s for a valid projected mapping update, 1m23.4s to
observe a malformed update rejection, and 1m17.4s for valid recovery. The file
runtime test already covers malformed processing ECDS rejection, retention,
and recovery. After the repeat runs, consider keeping one valid projected
ConfigMap reload in Kind and removing only the duplicate rejection and recovery
waits. Keep that as a separate iteration.

Done when: the overlap table above names a single owning live spec for each
resource reload contract, and the full suite still proves every listed
observable outcome.

#### 3.3 Trim setup and fixed waits only where measured (measurement tooling implemented; optimization pending)

`e2e/Makefile` pulls seven images and calls `kind load` on every run. Measure
these stages before adding a warm-cache fast path. Cache the pinned
cert-manager manifest if download time is material. Investigate the 60-second
bootstrap hold using evidence that the projected file changed inside the Pod.

Timing instrumentation is in place. No setup fast path or wait reduction has
been made; compare new warm and cold stage timings before choosing either.

### Phase 4: schedule the remaining work

#### 4.1 Benchmark worker counts (full suite passes; stability and comparison pending)

The green two-worker reports so far are `rrelfull1` at 10m50.6s and `rrelsp3`
at 8m17.6s; the latter includes the API-key lifecycle reduction. Run at least
two more warm full suites at `GINKGO_PROCS=2` to establish repeatability before
changing worker count or making another speed change. Then compare full runs
with `GINKGO_PROCS=3` and `4`. Compare `make e2e` wall time, per-container
times, failures, and Kind resource pressure. The current suite has 12
independent top-level `Ordered` groups with separate run-scoped namespaces and
no `Serial` groups. Ginkgo can run groups on different workers, while each
ordered group remains on one worker. The current default is two workers. Use
the fastest stable setting as the default; retain a lower setting for
resource-limited local machines if needed.

Done when: the chosen worker count improves the median without raising the
failure rate or causing timeouts.

#### 4.2 Split the remaining longest ordered group if needed (layout implemented; measurement pending)

The API-key cases now use three ordered groups: request decisions, Secret
projection, and namespace isolation. The request and projection groups use
fresh namespaces, so they can run on separate workers without sharing mutable
state. Compare full-suite wall time and worker pressure before adding more
groups.

One later topology option is a namespace per use case with multiple gateway
deployments in that namespace, for example separate JWT and API-key gateways
for authentication and authorization, plus a rotation namespace for TLS and
ECDS updates. [Request metrics](../e2e/request_metrics_test.go) already shows
that several behavior specs can share one configured JWT gateway.

To support multiple gateways in one namespace, add configurable
`kubernetes.name` and `kubernetes.labels` fields. The generator must use the
name for resource identities and stable selector labels, and propagate the
labels consistently to workload templates and their selectors. E2E pod lookup
and Envoy admin port-forwarding must target the configured identity. Preserve
the current defaults for a single gateway, then verify two named gateways can
serve requests and reload resources independently in one namespace. Benchmark
the namespace cleanup savings against extra Pods, setup waits, and resource
contention. Keep the namespace-isolation case separate.

Done when: each container runs alone, no cluster state is shared across
parallel workers, and the measured full-suite wall time falls.

#### 4.3 Set a runtime gate from stable data (pending)

Publish per-spec timing reports in CI and compare warm-run medians before and
after each phase. Target a passing full suite under 6m at a stable worker
count, about half the previous 12m10s median, with the coverage ledger
complete and distinct live scenarios retained. The three earlier runs span
12m3s to 13m25s. The 9m32s post-change attempt failed and skipped specs; the
10m50.6s run is the reliability checkpoint before the API-key wait reduction.
`rrelsp3` is the first full run after that reduction at 8m17.6s. Run two more
warm suites at the same worker count before treating the speed result as
stable.

Done when: a reviewer can see coverage added or preserved, the time saved,
and any new resource cost in the same change.

## Pre-change per-spec timing snapshot

The table is sorted by the median inclusive time of three runs. `S` means the
first spec includes container setup; `C` means the last spec includes cleanup.
Values below 0.1s are shown as `<0.1`. Worker assignment varied by run and is
not a property of the spec.

| Median seconds | Range seconds | Container | Spec | Hook |
| ---: | ---: | --- | --- | :---: |
| 180.2 | 154.0-187.3 | API-key authentication | revokes every key with an explicit empty Secret resource | C |
| 156.5 | 127.3-161.7 | API-key authentication | reloads mapped key attributes without replacing the Pod |  |
| 149.0 | 146.2-149.2 | API-key authentication | rotates the shared Secret across HTTP and HTTPS servers without replacing the Pod |  |
| 115.4 | 115.3-120.0 | Replicas and bootstrap rollouts | keeps bootstrap-only changes inactive until an explicit rolling restart | C |
| 101.6 | 89.4-105.5 | JWT access and identity processing | reloads mapping changes through ECDS without changing authorization or the Pod | C |
| 90.7 | 28.3-100.6 | Server TLS | reloads a renewed server certificate without restarting Envoy | C |
| 87.8 | 73.7-91.7 | Replicas and bootstrap rollouts | reloads processing configuration on both replicas without replacing either Pod |  |
| 75.5 | 67.3-84.5 | API-key authentication | retains the last accepted keys when a Secret update is invalid |  |
| 70.5 | 69.5-71.7 | Replicas and bootstrap rollouts | updates the server certificate on both replicas without replacing Pods | S |
| 59.4 | 48.9-61.0 | Tracing | exports a sampled span and keeps gateway metrics available | SC |
| 55.3 | 53.3-57.7 | JWT JWKS lifecycle | rotates keys without restarting the gateway and isolates a failing issuer | SC |
| 36.9 | 35.7-36.9 | Plain JWT authorization | rejects invalid credentials and denied claims before the upstream | C |
| 35.1 | 34.1-35.1 | HTTP routing and metrics | omits the metrics sidecar and Service port when metrics are disabled | C |
| 32.3 | 31.8-42.3 | Multi-replica server TLS | serves custom Service ports and reloads a TLS Secret on both replicas | SC |
| 29.2 | 29.1-30.2 | API-key namespace isolation | defaults to X-API-Key with independent namespace contents | SC |
| 29.1 | 28.1-107.6 | Header-sourced attributes | reloads header mappings without changing the Pod or raw grant | C |
| 27.0 | 27.0-27.0 | Direct JWT headers | rejects a missing required header attribute even when the caller supplies that header | C |
| 27.0 | 27.0-27.0 | Upstream TLS and HTTP/2 | rejects a mismatched upstream SAN and records the Envoy verification counter | C |
| 24.7 | 20.2-31.8 | HTTP routing and metrics | exposes scraped Envoy metrics |  |
| 14.8 | 13.7-15.0 | Server TLS | serves each HTTPS hostname only through its own TLS chain | S |
| 4.8 | 3.9-4.9 | JWT access and identity processing | counts a successful request with mapped labels |  |
| 4.5 | 4.4-7.5 | Header-sourced attributes | uses header-only JWT and key grants while forwarding mapped and original values | S |
| 4.3 | 3.4-4.4 | Direct JWT headers | replaces caller-supplied managed headers with verified values | S |
| 4.2 | 2.1-5.2 | Upstream TLS and HTTP/2 | verifies upstream TLS and sends HTTP/2 requests | S |
| 3.6 | 2.5-4.5 | API-key authentication | uses one Secret across protected servers and forwards verified attributes | S |
| 3.5 | 2.5-4.4 | JWT access and identity processing | authorizes original claims and sends processed attributes over HTTP and HTTPS | S |
| 2.7 | 1.2-3.2 | HTTP routing and metrics | forwards metrics | S |
| 2.4 | 2.3-4.5 | Plain JWT authorization | skips audience validation when none is configured | S |
| 0.8 | 0.8-0.8 | API-key authentication | counts mapped key attributes in response metrics |  |
| 0.8 | 0.3-0.8 | API-key authentication | uses a verified JWT first on a mixed any_of server |  |
| 0.8 | 0.8-0.8 | API-key authentication | requires both credentials and equal nonempty scalar attributes for all_of |  |
| 0.5 | <0.1-0.5 | API-key authentication | denies absent or unauthorized keys before the backend |  |
| <0.1 | <0.1-0.1 | Header-sourced attributes | denies absent credentials and missing or unlisted header values before the backend |  |
| <0.1 | <0.1 | JWT access and identity processing | rejects invalid credentials, missing required attributes, and denied original claims |  |
| <0.1 | <0.1 | Header-sourced attributes | requires matching nonempty raw values across headers, claims, and key credentials on all_of |  |
| <0.1 | <0.1 | Server TLS | exposes routes and method fallbacks only for bound APIs |  |
| <0.1 | <0.1 | Plain JWT authorization | authorizes each listed member and rejects an unlisted member |  |
| <0.1 | <0.1 | JWT access and identity processing | replaces unsafe or oversized label values |  |
| <0.1 | <0.1 | JWT access and identity processing | uses each API binding and excludes unmetered and fallback routes |  |
| <0.1 | <0.1 | JWT access and identity processing | scopes grants to individual APIs on the same hostname |  |
| <0.1 | <0.1 | Header-sourced attributes | keeps the verified JWT working value on mixed any_of |  |
| <0.1 | <0.1 | Direct JWT headers | authorizes with the original managed header before replacing it |  |
| <0.1 | <0.1 | JWT access and identity processing | counts an RBAC denial with a mapped tenant and missing writer |  |
| <0.1 | <0.1 | JWT access and identity processing | keeps the upstream response code |  |
| <0.1 | <0.1 | JWT access and identity processing | uses fallback labels for an invalid JWT |  |
| <0.1 | <0.1 | JWT access and identity processing | accepts a 128-byte printable label value |  |
| <0.1 | <0.1 | HTTP routing and metrics | rejects a regex path that does not match |  |
| <0.1 | <0.1 | HTTP routing and metrics | omits method fallbacks for unbound APIs |  |
| <0.1 | <0.1 | JWT access and identity processing | isolates JWT issuers by server |  |
| <0.1 | <0.1 | HTTP routing and metrics | serves the query host's bound API |  |
| <0.1 | <0.1 | HTTP routing and metrics | rejects an API not bound to the query host |  |
| <0.1 | <0.1 | HTTP routing and metrics | rejects unknown hosts |  |
| <0.1 | <0.1 | HTTP routing and metrics | rejects unknown paths |  |
| <0.1 | <0.1 | HTTP routing and metrics | rejects a prefix path without the trailing slash |  |
| <0.1 | <0.1 | HTTP routing and metrics | returns not found for a server with no APIs |  |
| <0.1 | <0.1 | HTTP routing and metrics | rejects other methods |  |
| <0.1 | <0.1 | Direct JWT headers | removes a managed input header on routes without that output |  |
| <0.1 | <0.1 | JWT access and identity processing | passes through authorized values without a mapping |  |
| <0.1 | <0.1 | HTTP routing and metrics | rewrites a regex path and preserves the query |  |
| <0.1 | <0.1 | HTTP routing and metrics | accepts multiple methods on one route |  |
| <0.1 | <0.1 | HTTP routing and metrics | rewrites a prefix path |  |
| <0.1 | <0.1 | HTTP routing and metrics | accepts POST on a route that also accepts GET |  |
| <0.1 | <0.1 | HTTP routing and metrics | uses the first declared matching route |  |
