# Production readiness review

Review date: 2026-10-09. Reviewed commit: `6d6be5e`, branch `main`.

This is a worklist, not a narrative. Each item is written so an agent can pick it
up on its own: what to change, where, why, and how to know it is done. Items are
grouped into phases. Phases are ordered by what blocks what. Inside a phase,
items are independent unless a dependency is stated.

## How to use this document

- Work one item at a time on a feature branch. Do not push or open PRs until asked.
- Follow `AGENTS.md` and `CONTRIBUTING.md`. They win over anything here.
- Tick an item only when its acceptance criteria pass, not when the code compiles.
- If an item turns out to be wrong, say so in the item rather than silently skipping it.

## Verified baseline

Everything below was run against the reviewed commit on 2026-10-09.

| Check | Command | Result |
| --- | --- | --- |
| Unit and golden tests | `make test` | pass |
| Statement coverage | `go test ./config -cover` | 93.1% |
| Lint | `make lint` | 0 issues |
| Vet with all build tags | `go vet -tags=e2e,envoyruntime ./...` | clean |
| Live end-to-end suite | `make e2e` | 46 of 46 specs pass in 5m29s |

The runtime image check (`make test-runtime`) was not run.

The engineering baseline is genuinely good. Tests pass, coverage is high, lint is
clean, and the end-to-end suite exercises the hardest logic in the product. The
gaps below are about what is missing around that core, not about a broken core.

Two things to keep in mind while reading. First, the repository has no remote
`main` and no tags, so none of the release-facing items have ever been exercised.
Second, several findings are consequences of a single root cause, so fixing the
root cause closes more than one item.

---

## Phase 0: release blockers

Small, cheap, and they unblock everything else. Do these first.

### 0.1 Add a LICENSE file [x]

There is no `LICENSE` in the repository root. Without one the default is "all
rights reserved", and no downstream consumer can legally vendor or import the
module. This is the single hardest blocker on calling the project a library.

Pick the license the organisation uses for this code, add the file, and add the
matching header policy if the organisation requires one.

Done when: `LICENSE` exists at the repository root and the README states the license.

### 0.2 Fix six broken documentation links [x]

The README already linked to `docs/auth/`, but the guides lived under
`docs/guides/auth/`. Their extra nesting level also made the four links from the
guides point to the wrong files. Moving the guides to `docs/auth/` keeps the
README links intact and makes all six links resolve.

| Location | Target | Resolves to |
| --- | --- | --- |
| `README.md:66` | `docs/auth/api-key.md` | `docs/auth/api-key.md` |
| `README.md:81` | `docs/auth/README.md` | `docs/auth/README.md` |
| `docs/auth/README.md:5` | `../../config.auth.example.yaml` | `config.auth.example.yaml` |
| `docs/auth/api-key.md:31` | `../envoy.md#api-key-secret-format` | `docs/envoy.md` |
| `docs/auth/api-key.md:81` | `../../config.auth.example.yaml` | `config.auth.example.yaml` |
| `docs/auth/jwt.md:56` | `../../config.auth.example.yaml` | `config.auth.example.yaml` |

Done when: every relative link in every markdown file resolves to an existing path.

### 0.3 Add a link checker to the lint target [x]

Item 0.2 was a silent regression that survived several commits. Add a link check
so it cannot happen again. A short shell loop over `grep`-extracted targets is
enough; no new tool dependency is needed.

Done when: `make lint` fails if any relative markdown link does not resolve.

### 0.4 Add continuous integration [x]

There is no `.github/` directory and no CI definition anywhere. `make test`,
`make lint`, `make test-runtime`, and `make e2e` all exist and all pass, but
nothing runs them automatically.

Add a workflow that runs, on pull request:

1. `make lint`
2. `make test`
3. `go test -tags=e2e,envoyruntime -run '^$' ./...` to compile tagged packages
4. `make e2e`
5. `make test-runtime`

Done when: a pull request runs all five checks and fails on any of them.

### 0.5 Add repository governance files [x]

Missing from the root: `SECURITY.md`, `OWNERS` or `CODEOWNERS`, `CHANGELOG.md`.
For an authentication component, a vulnerability reporting path is not optional.

Also: `.idea/` is present in the working tree, is not tracked, and is not in
`.gitignore`. Add it.

Done when: the three files exist and `.gitignore` covers `.idea/`.

---

## Phase 1: make it usable as a library

The package is documented as a library but cannot be adopted as one without
reading the source. This phase is the highest-value work in the review.

### 1.1 Add runnable Go examples [x]

There is no Go code in any documentation file, no `example_test.go` anywhere, and
the module import path `github.com/rhobs/auth-gateway` appears in no document.
A consumer reading the README is told to "load a gateway YAML document with
`config.Load`, call `config.GenerateKubernetes`, then write `resources.YAML()`"
and must infer every signature.

Add `config/example_test.go` with compiled examples:

- `ExampleLoad` reading from a string reader, with error handling.
- `ExampleGenerate` showing the returned map and writing each entry to disk.
- `ExampleGenerateKubernetes` through to `YAML()` and a manifest file.
- `ExampleAPIKeySecret` covering `LoadAPIKeyCredentials` into `APIKeySecret`.

Examples compile under `make test`, so they cannot rot. Mirror the shortest one
into the README with the import line and a `go get`.

Done when: `go doc github.com/rhobs/auth-gateway/config` shows usage, and the
README contains one compiling Go snippet.

### 1.2 Export the generated file layout [x]

`Generate` returns `map[string][]byte` with keys the consumer must guess, and the
generated bootstrap hardcodes absolute paths that the consumer must reproduce on
disk. Those paths live in unexported constants, so a change to them silently
breaks every file-based deployment.

| Path baked into the bootstrap | Defined at | Documented |
| --- | --- | --- |
| `/etc/auth-gateway/envoy.yaml` | `config/kubernetes.go:93` | no |
| `/etc/auth-gateway/processing/processing.yaml` | `config/generate.go:375` | only as a Kubernetes mount |
| `/etc/auth-gateway/api-keys/api-keys.yaml` | `config/api_keys.go:241` | yes |
| per-HTTPS-server certificate resource file | `config/generate.go:963` | no |
| `/etc/auth-gateway-ca/<hashed id>/ca.crt` | `config/types.go:580` | directory only, not the hashed subpath |

Either export constants for the filenames and directories, or change `Generate`
to return a typed result that names each output and its required location.
A typed result is the better shape and the breaking change is cheap now, while
there are no tagged releases and no external consumers.

Done when: a consumer can place every generated file correctly without reading
unexported identifiers, and `docs/envoy.md` states the required on-disk layout
for file-based output in one place.

### 1.3 Define the error contract [x]

Every failure is a bare `fmt.Errorf` string. There are no exported sentinel
errors and no exported error types, so `errors.Is` and `errors.As` are unusable.
Some sites use `%s` rather than `%w` and do not wrap at all. No document states
what `Load` returns on failure, or that it returns a zero `Config` rather than a
partial one.

Minimum: document that errors are opaque and message-only, so consumers do not
start matching on strings by accident.

Better: introduce one exported error type carrying the configuration field path.
Validation already computes that path for every message, so the information is
there and is being thrown away into a string.

Done when: the package doc states the contract, and if a typed error is added,
`Load` and `Validate` return it for every validation failure.

### 1.4 Document the deployment-mode split on trusted CAs [x]

`TrustedCA.Filename` (`config/types.go:246`) appears in no example and no
document. It is also the only CA option that works without Kubernetes:
`config/trust.go:29` rejects `config_map` when Kubernetes settings are absent,
and `config/trust.go:40` rejects `filename` when they are present.

So a file-based consumer who copies `trusted_ca: {config_map: ...}` from
`config.auth.example.yaml:50` hits a hard validation failure with no documented
alternative.

Done when: the README and `docs/envoy.md` state that the CA field differs by
deployment mode, and at least one example shows `filename`.

### 1.5 Fill the godoc gaps [x]

- The package comment was one sentence at the reviewed commit. It has since been
  expanded with an entry-point map, including `Config.Validate` for configurations
  built in Go.
- Three exported methods have no doc comment: `Duration.String`,
  `Duration.UnmarshalYAML`, `Duration.MarshalYAML` (`config/duration.go:15,17,32`).
- `KubernetesResources` (`config/types.go:279`) has six exported fields and no
  field comments, despite being the primary return value. Nothing says
  `ProcessingConfigMap` and `OTelCollectorConfigMap` are nil-able. They are.
- `Config.Validate` already had a Go doc comment in the reviewed source, so the
  claim that it was undocumented was incorrect. The package overview now points
  Go callers building a `Config` directly to it.

Done when: every exported identifier has a conventional doc comment.

### 1.6 Add constructors for pointer fields [x]

The schema uses pointers throughout to distinguish "unset" from "zero". A
consumer building a `Config` programmatically has to hand-roll a pointer for
every duration, count, and flag. The test suite has an unexported `duration`
helper for exactly this reason.

Export a small set of helpers, at minimum one for `Duration`. Note that Go 1.26
`new(expr)` covers the simple cases, which is a reason to keep this minimal.

Done when: an example in `config/example_test.go` builds a non-trivial `Config`
in Go without defining local helpers.

### 1.7 Remove internal history from public documentation [x]

These are written relative to a refactor the reader never saw:

- `config/types.go:112`: "the OpenTelemetry Collector Contrib image used by the PoC".
  "the PoC" is meaningless externally and this comment is on pkg.go.dev.
- `README.md:117` "the existing stats-only Lua filter".
- `docs/envoy.md:29` "the existing Lua response counter".
- `docs/envoy.md:49` "No new Lua handles authentication or attributes".

Done when: no public document or doc comment refers to a prior state of the code.

### 1.8 Add a configuration field reference [x]

There is no page listing fields, types, defaults, and constraints. The four
example YAMLs are the de-facto reference. About thirty fields appear only as
example lines with no stated semantics or bounds, and the bounds are not
guessable: `max_request_headers_kb` caps at 8192 (`config/types.go:598`), HTTP/2
window sizes run 65535 to 2147483647 (`config/types.go:660`), overload thresholds
are exclusive between 0 and 1 (`config/types.go:693`).

The documentation chain goes overview, then task guides, then Envoy internals.
The reference tier is missing.

Done when: `docs/` contains a reference page covering every YAML field with its
type, default, and constraint, generated or hand-written.

### 1.9 Move the API-key Secret format into the user guide

`docs/envoy.md:83-138` holds the API-key Secret format. That is the single most
important thing a consumer must provide out-of-band, and it is buried in the
internals document under "Kubernetes files and reloads". The user guide has to
link out to it, through one of the broken links in item 0.2.

`AGENTS.md` says user guides should cover "resources users must provide", which
is exactly this section.

Done when: the Secret format lives in `docs/guides/auth/api-key.md` and
`docs/envoy.md` links to it rather than owning it.

### 1.10 Correct the `any_of` wording

`docs/guides/auth/README.md:12` says "`any_of` accepts one selected method".
Read literally that says the list may hold only one authenticator, which
contradicts `config.auth.example.yaml:206` and the code. The intended meaning is
that one of the selected methods must succeed. `README.md:71` and
`docs/envoy.md:51` both state it correctly.

Done when: the guide matches the README.

### 1.11 Fix the stale test ownership table

`CONTRIBUTING.md:52-53` names three files that do not exist
(`config/defaults_test.go`, `config/jwks_test.go`, `config/jwt_generate_test.go`)
and omits five that do (`api_keys_test.go`, `cel_test.go`, `duration_test.go`,
`observability_test.go`, `runtime_test.go`). The recent test consolidation
commits moved the content and left the table behind.

Done when: the table matches the files on disk.

### 1.12 State the Go version and versioning policy

`CONTRIBUTING.md:3` records the Go 1.26 floor, but that is a contributor
document. A consumer reading only the README has no idea the module needs a very
recent toolchain. Go 1.26 is also an aggressive floor for a library; most target
one or two releases back. If the floor is deliberate, say so and say why.

Separately: there are no tags, so consumers get a pseudo-version. Nothing states
whether the YAML schema version and the Go API version move together, or what
happens at schema `version: 2`.

Done when: the README states the Go floor, the stability policy, and the
relationship between the schema version and the module version.

---

## Phase 2: code organisation and correctness

No bugs were found that produce wrong output today. These are structural issues
that make the code hard to change safely, plus three latent hazards.

### 2.1 Split the five oversized functions

| Function | Lines | File |
| --- | --- | --- |
| `GenerateKubernetes` | 283 | `config/kubernetes.go:57` |
| `toHTTPManager` | 196 | `config/generate.go:254` |
| `generate` | 156 | `config/generate.go:82` |
| `Config.validate` | 152 | `config/config.go:121` |
| `validateAuthentication` | 151 | `config/config.go:546` |

`GenerateKubernetes` builds a ConfigMap, a ServiceAccount, a Deployment, five
kinds of volume mount, and a Service in one body. Each volume-mount block is an
independent concern and extracts cleanly.

`toHTTPManager` is the worst of the five to reason about: the filter list is
assembled through nested conditionals that re-ask `c.usesAPIKeys()`,
`hasProtectedHosts(hosts)`, and `c.hasAttributeMappings()` at several depths, and
the credential cleanup filter is appended from two different branches
(`config/generate.go:392` and `:407`) at different positions.

Done when: no function in `config/` exceeds roughly 80 lines, golden files are
unchanged, and `make test` passes without regenerating goldens.

### 2.2 Remove the duplicated attribute-filter branch

`config/generate.go:360-371` has two consecutive blocks guarded by the identical
condition:

```go
attributeFilter := &hcm.HttpFilter{Name: attributeFilterName}
if !c.hasAttributeMappings() {
    // ... set attributeFilter.ConfigType
}
if !c.hasAttributeMappings() {
    filters = append(filters, attributeFilter)
}
```

When mappings exist, `attributeFilter` is constructed and discarded. Collapse to
one block.

Done when: one guarded block remains and goldens are byte-identical.

### 2.3 Fix the host-to-server index alignment hazard

`config/generate.go:255-263` builds `serverIndexes` by matching
`server.Hostname == host.Name` and appending on match. `config/generate.go:339`
then iterates with `for hostIndex, serverIndex := range serverIndexes` and
indexes `hosts[hostIndex]`.

That only holds while every host finds a match. If one does not, nothing is
appended, the slices silently misalign, and per-filter configuration is written
to the wrong virtual host. The same loop writes into
`hosts[hostIndex].TypedPerFilterConfig`, which is nil for a server without
authentication; today that is unreachable only because an earlier `continue`
happens to fire first.

Carry the server index on the host rather than recovering it by name, or return
an error when a host does not match.

Done when: the pairing is structural rather than positional, and no path can
write into a nil `TypedPerFilterConfig`.

### 2.4 Guard the unchecked slice index

`config/generate.go:700` does `principal := principals[0]` with no length check.
It is safe today because the caller only runs with a non-empty mapping list, but
a library should not panic on a caller's input.

The same applies to `resource.MustParse` in `kubernetesResourceList`
(`config/kubernetes.go:390`). Validation parses the same quantities first, so the
panic is unreachable today, but it is one refactor away from being a library
panic rather than an error return.

Done when: neither site can panic regardless of input.

### 2.5 Resolve the defaulting and validation duplication

`Load` applies defaults at `config/config.go:108`, then calls `Validate`, which
calls `resolveConfig`, which applies defaults again at `config/config.go:963`.
`Generate` and `GenerateKubernetes` each call `resolveConfig` and apply them a
further time. A consumer doing `Load` then `Generate` then `GenerateKubernetes`
runs full defaulting and validation four times.

Defaults are idempotent so there is no wrong output, only waste and confusion.
There is also a real asymmetry worth deciding on deliberately: the `Config` that
`Load` returns has defaults applied but route timeouts unresolved, because
`resolveConfig` resolves them on a copy that is discarded. `docs/envoy.md:15`
documents this, so it may be intended, but nothing in the godoc says it.

Done when: defaulting runs once per public entry point, and the `Load` return
contract is stated in its doc comment.

### 2.6 Collapse the duplicated grant collection

`toServerRBACRules` (`config/generate.go:528-576`) contains the same
grant-collection loop twice, once in the `any_of` branch and once in the `all_of`
branch, differing only in how the results are combined. Extract the shared loop.

Done when: the loop body appears once and goldens are unchanged.

### 2.7 Reconsider the goconst-driven error format constants

`.golangci.yml` sets `goconst` to `min-occurrences: 2`. That threshold forced a
family of format-string constants into existence: `readGatewayConfigErrorFormat`,
`fieldWrapErrorFormat`, `apiBindingErrorFormat`, `apiNameValidationErrorFormat`,
`enableAttributesErrorFormat`, `protoValidationErrorFormat`.

The result is that `fmt.Errorf(apiNameValidationErrorFormat, name)` tells a
reader nothing at the call site. The linter configuration is driving the design,
and the readability cost exceeds the benefit. Also note that
`config/config.go:78` writes the nil-reader message as a literal while the
neighbouring sites use the constant, so the convention is not even uniform.

Raise `min-occurrences` to 3 or 4 and inline the error strings.

Done when: error messages read inline at their call sites and `make lint` passes.

### 2.8 Deduplicate the collector configuration templates

`config/observability.go:81-176` holds three hand-written YAML templates filled
by positional `fmt.Sprintf` arguments. The scrape block appears in two of them,
so changing it means editing both. `tracing.Endpoint` is interpolated straight
into YAML; it is validated as a host and port without control characters, so
injection is bounded, but the approach is inconsistent with the typed protobuf
construction used everywhere else in the package.

Build a typed structure and marshal it.

Done when: one source of truth for the scrape configuration, and goldens plus
`make test-runtime` both pass.

### 2.9 Decide the position on the Lua request counter

`AGENTS.md` says to keep handling in native Envoy filters and not to reintroduce
Lua. Per-API request counters are implemented as an inline Lua script
(`config/observability.go:445-495`) and the filter is literally named
`envoy.filters.http.lua` (`config/observability.go:44`).

This has three knock-on effects:

1. The collector configuration carries a `replace_pattern(name, "^envoy_http_lua_", "")`
   transform purely to undo the Lua stat prefix.
2. `requestMetricsFilterName` doubles as the route metadata namespace key, so a
   second Lua filter would collide with it.
3. The documentation has to explain the Lua prefix to users.

Either document the exception in `AGENTS.md` with the reason, or plan the
replacement. Do not leave the rule and the code disagreeing.

Done when: `AGENTS.md` and the code agree.

### 2.10 Retire the deprecated Envoy field

`config/cel.go:101` suppresses `staticcheck` with the note "Keep the Envoy wire
form stable during this cleanup", and four test sites carry the same suppression.
The cleanup referenced is finished. Migrate off the deprecated
`SubstitutionFormatString` text format before tagging a release, or restate why
it must stay.

Done when: either the suppressions are gone, or the comment explains a current
reason rather than a finished cleanup.

### 2.11 Improve golden failure output

`checkReference` (`config/generate_test.go:95`) reports only
"<path> is out of date; run make update-golden". A developer gets no indication
of what changed. Print a diff. `github.com/google/go-cmp` is already an indirect
dependency.

Done when: a failing golden prints the differing content.

### 2.12 Split the compound test assertions

Assertions such as `config/config_test.go:197` combine eight field comparisons in
one boolean expression and then dump the whole protobuf on failure. The pattern
recurs across the config tests. When one of them fails, finding out which field
is wrong means reading a protobuf dump.

This is a diagnosability problem, not a correctness one. Prefer per-field
assertions or a single structural comparison with a diff.

Done when: a deliberately introduced single-field regression names the field in
the failure output.

### 2.13 Remove the playground golden-update side effect

`playground/Makefile` target `generate` runs
`go test ../config -run '^TestPlaygroundBootstrap$' -count=1 -update`, and
`start` depends on `generate`. So starting the playground rewrites the
checked-in `playground/envoy.yaml.golden`.

`CONTRIBUTING.md` warns against regenerating goldens to hide an output change.
The playground workflow does exactly that, silently, as a side effect of running
a demo.

A small generator program under `cmd/` would be more honest, and would double as
the runnable library example that item 1.1 needs.

Done when: running the playground does not modify checked-in goldens.

### 2.14 Reduce image pin duplication

`envoyproxy/envoy:v1.39.1` appears in about 25 places and
`otel/opentelemetry-collector-contrib:0.135.0` in about 10, spread across the
README, both Makefiles, the compose file, the example configs, every golden
testdata config, every e2e fixture, `config/observability.go:30`,
`config/runtime_test.go:82`, and `e2e/jwt_test.go:784`.

Some of that is inherent to checked-in testdata. The avoidable part is the
non-testdata copies, which drift independently.

Done when: the non-testdata pins come from one place, and a bump is a one-line
change plus a golden refresh.

---

## Phase 3: end-to-end coverage gaps

The existing suite is strong where it covers: JWT verification and its failure
modes, JWKS lifecycle, API-key rotation and revocation, `any_of` and `all_of`
selection, ECDS reload without pod churn, SNI and certificate rotation, and
metric label sanitisation. Negative cases consistently prove the backend was not
reached, which is the right discipline.

The gaps cluster in three places: routing primitives the examples lead with,
authorization scoping and upstream security, and operational surfaces.

Note that `AGENTS.md` rules out end-to-end tests for Envoy semantics such as
timeouts, retries, overload, and flow control. Items below stay on the gateway's
own behavior. Item 3.8 is the one borderline case and is marked optional.

### 3.1 Prefix and regex path matching and rewriting

Risk: high. Zero live coverage. All seven fixtures use `path.exact` with
`rewrite.path`. Prefix and regex matching are headline features in
`config.example.yaml:67-98` and are used in the `route-lists` golden. The regex
engine was changed recently (`9ca4dfd Use Envoy's default regex engine`) with no
live test behind it.

Scenario. Add one API to `e2e/fixtures/gateway.yaml`, bound to the existing
`auth.auth-gateway.test` server:

- `GET` with `regex: '^/metrics/api/v1/(query|query_range)$'` and
  `rewrite.regex` of pattern `^/metrics/(.*)$` to substitution `/anything/\1`.
- `GET` with `prefix: /logs/otlp/` and `rewrite.prefix: /anything/otlp/`.

Requests and assertions:

| Request | Expect |
| --- | --- |
| `GET /metrics/api/v1/query_range?x=1` | 200, echoed path ends `/anything/api/v1/query_range`, query preserved |
| `GET /logs/otlp/v1/logs` | 200, echoed path ends `/anything/otlp/v1/logs` |
| `GET /metrics/api/v1/queryXrange` | 404, upstream request counter unchanged |
| `GET /logs/otlp` | 404, upstream request counter unchanged |

### 3.2 API-scoped authorization grants

Risk: high. `AuthorizationGrant.APIs` is the only thing stopping a tenant
authorised for one API from reaching another on the same hostname. Every fixture
grants the full bound set to the same tenants, so the scoping is never exercised
live. Only `config/generate_test.go:973` covers it.

Scenario. In `e2e/fixtures/jwt-gateway.yaml`, split the writer policy so one
tenant is granted `[metrics]` only and another `[status-only]` only, both still
bound to the same hostname. Then assert each tenant gets 200 on its own API and
403 on the other, with the other API's upstream counter unchanged.

### 3.3 Upstream TLS and HTTP/2 upstreams

Risk: high. `config.production.example.yaml:52-57` ships upstream TLS with a
`trusted_ca.config_map` as the production pattern. The generated cluster carries
an SNI name, a trust bundle at a hash-derived mount path, and ALPN selection.
None of it is driven with traffic. The identical CA-mount machinery is exercised
for JWKS (`e2e/jwt_test.go:540`), which is partial mitigation only.

Scenario. Add a TLS-fronted backend, reusing the small-Envoy pattern already in
`e2e/jwt_test.go:719` and the certificate helper at `e2e/jwt_test.go:686`.
Configure one API with `upstream.tls_config` naming the SAN plus a
`trusted_ca.config_map`, and a second with `http_protocol: http2`. Assert a
full echo on success, and a connection failure with the matching Envoy
`ssl.fail_verify_san` counter when `server_name` does not match the SAN.

### 3.4 Tracing

Risk: medium-high. Tracing changes both the bootstrap and the collector
ConfigMap, and is user-facing in `config.example.yaml:27-33`. Generation is
tested (`config/observability_test.go:403`) and the collector config is validated
by the real binary (`config/runtime_test.go:23`), but nothing proves a span
leaves Envoy.

Scenario. One container with tracing enabled at 100 percent sampling pointing at
an in-cluster OTLP sink. Make one authorised request, then assert the sink
observed a span whose service name matches `service_name`. Also assert the
gateway pod still has two containers and metrics are unaffected.

### 3.5 Error access logs

Risk: medium. `config/access_log.go` emits structured JSON to stdout for every
response at 400 or above, including `response_flags` and `response_code_details`.
This is the primary operational debugging surface and has no test at all.

Scenario. Cheap to add to the existing JWT container. The framework already
reads pod logs in `Diagnostics` (`e2e/internal/framework/environment.go:577`);
promote that to an exported helper. After the invalid-credentials spec, assert a
JSON line exists with status 401 and a non-empty `response_code_details`, and
that no line exists for the preceding 200, which proves the filter threshold.

### 3.6 Multiple replicas

Risk: medium. Every fixture pins `replicas: 1`, and `framework.PodUID`
(`e2e/internal/framework/environment.go:343`) hard-fails unless exactly one pod
matches, so the framework actively prevents testing this. The production default
is `replicas: 2` (`config/config.go:71`).

Untested at more than one replica: ECDS and SDS fan-out to all pods, per-pod
JWKS cold caches, and continuous service during a rolling update.

Scenario. Add `framework.PodUIDs` returning a sorted set. Run one container at
two replicas. After a processing ConfigMap update, loop about twenty requests so
both pods are hit and assert all return the new mapping with the pod UID set
unchanged. During a restart, assert a concurrent request loop sees no connection
errors and no 5xx.

### 3.7 The documented rollout invariant

Risk: medium. `AGENTS.md` states that static bootstrap changes require an
explicit Deployment rollout and that there is no checksum annotation. The three
reload specs prove the ECDS half, that a mapping change does not restart pods.
Nothing proves the other half, so a user following the documentation has no
regression guard.

Scenario. In the JWT container, change something bootstrap-only, for example an
`apis[].metrics.labels` binding, which `config/observability_test.go:532`
confirms touches only the main ConfigMap. Apply only that ConfigMap, assert the
behavior is unchanged after a bounded wait with a stable pod UID, then restart
and assert the new behavior appears.

### 3.8 Route timeout placement (optional)

`AGENTS.md` says not to test Envoy timeout semantics end to end, and that is the
right line. The residual risk is placement rather than semantics: a per-route
`response_timeout` attached to the wrong route would not be caught by a golden
diff if the golden were regenerated.

If you want one spec, make it minimal. One route with a one-second response
timeout pointed at a three-second delay, asserting 504 and the upstream timeout
counter, plus a sibling route on the same API inheriting the default and
returning 200 from a two-second delay. Two requests, catches misplacement,
does not test Envoy's timer.

### 3.9 Smaller untested surfaces

Each is low risk on its own. Batch them.

- API-key default header `X-API-Key` (`config/auth.go:19`). Every fixture
  overrides it with `X-Partner-Key`, so the default path is never exercised.
- `observability.metrics.enabled: false`. Nothing confirms the collector
  container and the 8889 Service port actually disappear from a live deployment.
- `envoy_concurrency`, non-default `resources`, non-default `service_port` and
  `https_service_port`.
- Multiple methods on one route, and route declaration-order precedence.
- Explicit `tls_config.certificate` and `private_key` paths. They are set in
  `e2e/fixtures/jwt-gateway.yaml:151` but nothing asserts Envoy loaded them.
- A server with no `apis` list.
- JWKS `fetch_timeout`, `connect_timeout`, and circuit breakers.

---

## Phase 4: end-to-end suite quality

The suite passes reliably today. These items reduce runtime, remove flakiness
risk, and make specs independently runnable.

### 4.1 Remove the per-request HTTPS port-forward

`e2e/api_keys_test.go:460-474`: when TLS is requested, `request()` opens a new
SPDY port-forward with a one-minute dial timeout and tears it down, per request.
The `all_of` spec at `e2e/api_keys_test.go:128` makes seven such calls. Every
other container forwards once in setup.

This is the largest single source of flakiness risk and runtime cost in the
suite. Forward 443 once in `setupAPIKeyGatewayWithShape` and store it alongside
`httpAddr`.

### 4.2 Break the hidden ordering dependencies in the API-key container

Specs in `e2e/api_keys_test.go` mutate durable cluster state that later specs
depend on:

- `:157` counts `team-a`, then `:170` rewrites the mapping to `team-c` and never
  restores it.
- `:205` rotates the Secret so only `key-b` works. Both `:238` and `:259` assume
  that state without re-establishing it.

No spec in this container is independently runnable under `--focus`, and a
failure mid-container cascades into the rest. Make each spec set up, assert, and
restore.

### 4.3 Right-size the spec timeouts

`--timeout=30m` across two processes. The TLS container budgets
`NodeTimeout(18m)` for setup (`e2e/tls_test.go:19`) plus `SpecTimeout(9m)` for
rotation (`e2e/tls_test.go:119`), about 28 minutes in one process. If the routing
container's `NodeTimeout(12m)` lands in the same process, the suite timeout is
reachable with no product failure at all.

Separately, `e2e/jwt_test.go:134`, `:188`, and `:320` each carry
`SpecTimeout(12m)` for specs that make between one and six requests against an
already-warm gateway. A hang there burns twelve minutes before reporting.

The observed full run was 5m29s with warm images, so these budgets are roughly
two orders of magnitude above the real cost.

### 4.4 Consolidate the duplicated test helpers

- Three near-identical gateway setup helpers in three different styles:
  `setupGateway` (`e2e/support_test.go:46`), `setupJWTGateway`
  (`e2e/jwt_test.go:544`), `setupAPIKeyGatewayWithShape`
  (`e2e/api_keys_test.go:311`). All do the same eight steps. Two different
  warm-up implementations exist.
- The anonymous httpbin echo struct is redeclared in about ten places. One named
  type with a decode helper removes all of them.
- The "snapshot upstream counter, request, re-snapshot" pattern appears four
  times, twice inline and twice as near-identical helpers.
- Three parallel CA pools and two separate TLS client constructions.
- `e2e/jwt_test.go:674` writes the shared `rootCAs` global as a pure side effect.
  No JWT spec reads it. Delete it.

### 4.5 Fix the helper placement inversion

`AGENTS.md` assigns reusable Kubernetes lifecycle, port-forwarding, readiness,
and diagnostics to the framework, and fixture shaping, protocol clients, and
scenario assertions to the test package. Current placement drifts:

- Envoy admin access is reimplemented four times: once privately in
  `e2e/internal/framework/diagnostics.go:19` and three times in the test package
  (`e2e/jwt_test.go:876`, `e2e/api_keys_test.go:512`,
  `e2e/request_metrics_test.go:262`). An admin client is clearly framework
  infrastructure.
- `jwtUpstreamRequests` lives in `e2e/jwt_test.go:876` but is called with
  `api-ingest` and `api-header-ingest` from two other files. It is a generic
  cluster counter helper and is misnamed.
- Several cross-file helpers live inside the JWT spec file: `yamlDocuments`,
  `makeJWTTestCertificates`, `jwtIssuerManifest`, `headerValue`, `jwtTrustedCA`,
  and the token machinery. Meanwhile `e2e/support_test.go` holds routing and TLS
  state that only two files use. The split is inverted.
- `e2e/internal/framework/forward_test.go` uses the deprecated
  `fake.NewSimpleClientset`.

### 4.6 Strengthen the weak assertions

- `e2e/tls_test.go` never reads a response body. `requestHTTPSWithMethod`
  discards it (`e2e/support_test.go:175`), so `e2e/tls_test.go:63` asserts a 200
  for a POST without confirming the method, rewritten path, headers, or body
  reached the backend. `CONTRIBUTING.md:59` requires that check.
- `e2e/http_test.go` never verifies that denied requests miss the backend. Every
  other spec file does the before-and-after counter check. The
  "API not bound to this host" case at `e2e/http_test.go:65` is
  authorization-adjacent and deserves it.
- `e2e/http_test.go:64` asserts a bare 200 because the rewrite targets
  `/status/200`, which returns an empty body. Rewriting to `/anything` would let
  the test verify the rewrite actually happened.
- `checkPrometheusMetrics` (`e2e/support_test.go:192`) greps for the substring
  `envoy_server_live`. It does not confirm gateway HTTP stats are present or that
  the admin port is unexposed. The stronger `checkExportedRequestMetric`
  (`e2e/request_metrics_test.go:298`) already exists and is not reused.
- `e2e/jwt_test.go:111` asserts a 200 across three list-claim sub-cases without
  distinguishing which member drove the decision, so all three are
  indistinguishable from "any valid token passes".

### 4.7 Reduce stack duplication

`e2e/request_metrics_test.go` stands up a second complete copy of the
`jwt-gateway.yaml` stack, including JWKS Envoy, httpbin, gateway, and collector,
while `e2e/jwt_test.go:263` already runs the same fixture. That is one of ten
stacks spent on counter isolation that the specs' own before-and-after deltas
already provide.

### 4.8 Re-establish port forwards after pod replacement

Only `e2e/jwt_test.go:517` re-forwards after a deployment restart. Any future
spec that restarts a deployment and reuses a stored address will silently talk to
a dead forward. Make the framework handle this, or document the requirement next
to `RestartDeployment`.

Also: `e2e/support_test.go:91` allows fifteen seconds for the first successful
upstream request after readiness. On a cold Kind node that is tight next to the
three-minute warm-up budgets the JWT and API-key setups use.

### 4.9 Scope the failure reporter correctly

`ReportAfterEach` in `e2e/suite_test.go:25` reads the package-level
`activeNamespace`, which three different setup functions write
(`e2e/support_test.go:47`, `e2e/jwt_test.go:545`, `e2e/api_keys_test.go:312`).
A failure outside a container's own spec body can capture diagnostics from the
wrong namespace.

Also remove the inline diagnostics calls at `e2e/jwt_test.go:288` and `:382`,
which duplicate what the reporter already does.

---

## Phase 5: housekeeping

### 5.1 Prune stale branches

Seventeen local branches exist and only one has a remote counterpart. `main`
itself has never been pushed. Decide which branches are live before the first
push.

### 5.2 Fix the two defects in AGENTS.md

- `AGENTS.md:10` is an empty bullet.
- `AGENTS.md:9` hardcodes a machine-local absolute path,
  `/Users/pgough/Desktop/projects/regional-observability-service`. It means
  nothing to another contributor or to CI.

---

## Suggested ordering

Phase 0 is half a day and unblocks the rest. Phase 1 is the work that converts
this from "a package that generates Envoy config" into "a library someone can
adopt", and item 1.2 should be settled before any version is tagged because it is
a breaking API change that is free today and expensive later.

Phase 2 and Phase 3 are independent of each other and can run in parallel.
Within Phase 3, items 3.1 through 3.3 carry the real feature risk; 3.4 through
3.7 are operational confidence.

Phase 4 is maintenance payback rather than risk reduction, with the exception of
4.1 and 4.3, which both affect suite reliability and should be pulled forward if
end-to-end tests start appearing in CI.
