# Handoff: code, tests, and documentation cleanup

Updated: 2026-10-03.

The user requested this document for a follow-on implementation agent. The
remaining cleanup belongs to that agent. Keep the partial code changes listed
below, as the user requested.

## Scope and agreed decisions

Review the whole repository for quality, organization, and duplication. Include
production code, test infrastructure, tests, fixtures, examples, and build tools.

- Preserve public Go signatures, YAML fields, defaults, generated resource names,
  and gateway behavior. Record suggested API improvements separately.
- Keep the consolidated file layout. Every receiver method must live in the file
  that declares its receiver type. This includes the e2e framework.
- Use constants for repeated strings and identifiers shared with tests.
- Keep golden regression checks.
- Supply explicit YAML snippets or fixtures in tests. Do not construct test YAML
  with string replacement.
- Add local linting only. No CI workflow is required.
- Write concise end-user documentation in simple technical English (STE).
  Configuration authors are the primary audience. Explain Envoy internals in a
  separate technical document.

These decisions supersede the old handover's permission to make breaking API
changes and the review-only golden policy in `AUTH-PLAN.md`.

## Current workspace and work already done

Branch: `code-quality-cleanup`, created from `production-configuration` at
`8be60ba`. No new commits or pushes were made.

There are changes to 11 existing implementation files and a new
`.golangci.yml`, in addition to this handoff update:

| Area | Changes already made |
| --- | --- |
| JWT e2e setup | Removed two calls to the missing `setGatewayImage` helper in `e2e/jwt_test.go`. The fixtures already specify the Envoy image. |
| Config methods | Moved 11 `Config` methods from `config/servers.go`, `config/auth.go`, and `config/trust.go` into `config/config.go`. Imports were adjusted. |
| Framework methods | Moved 18 `Environment` methods from the framework's Kubernetes, cert-manager, forwarding, and diagnostics files into `e2e/internal/framework/environment.go`. Imports were adjusted. |
| Lint setup | Added `.golangci.yml` and `make lint`. The target checks formatting and invokes golangci-lint v2.14.0 through version-pinned `go run`. |
| Local tooling | Downloaded and built golangci-lint v2.14.0. Its version command succeeded with Go 1.26.6. |

The lint config includes tests and the `e2e` and `envoyruntime` build tags.
It enables `govet`, `staticcheck`, `errcheck`, `ineffassign`, `unused`,
`goconst`, and `dupl`. Repeated strings are checked after two occurrences,
including call arguments; the duplicate-code threshold is 150 tokens.

**The implementation changes have not been compiled, tested, or linted.**
The method moves are partial cleanup. Review the remaining source files for
constants or helpers that should now be consolidated.

Before these changes:

- `go test ./...` passed.
- `go vet ./...` passed.
- `go test -tags=e2e ./e2e/internal/framework` passed.
- `go test -tags=e2e,envoyruntime -run '^$' ./...` failed because the two
  `setGatewayImage` calls had no definition.

Live Kind e2e and runtime image checks were not run in this session. Historical
test results from earlier feature work do not validate this working tree.

## Behavior to preserve

- Load one strict YAML document. Keep caller-owned configuration unchanged,
  including nested maps, slices, pointers, and inherited route overrides.
- Preserve exact host bindings, API and route order, scoped route conflicts,
  rewrites, and local 404/405 behavior with the correct `Allow` header.
- Keep native JWT verification, authorization against original verified claims,
  ordered attribute processing, required-header checks, and credential removal.
  Preserve both issuers, server isolation, and protection from spoofed headers.
- Keep Envoy 1.39.1's native filter path. Its `envoy.string` values are bytes;
  unmatched mappings use `skip_if_empty` for passthrough. Do not restore Lua or
  the unsupported CEL `string(bytes)` conversion.
- Mapping updates change only the processing ConfigMap. Test that authorization
  still uses original claims, the backend receives the new value, and the Pod UID
  stays unchanged. Downstream certificate updates reload through SDS.
- Static configuration and CA changes require a rollout. There is no generated
  checksum annotation.
- Keep mTLS as future work and retain its clearly labelled example. New
  authentication features and unresolved Jira acceptance questions are outside
  this cleanup.

## Remaining implementation

### Code and linting

1. Check the existing diff and run compilation and linting first.
2. Finish receiver placement across the repository. Keep `Server` and
   `ServerTLS` methods with their types. Group related methods and remove files
   made unnecessary by consolidation. Do not turn methods into free functions
   just to bypass the placement rule.
3. Replace redundant collection helpers with standard library functions, such
   as `slices.Contains`, `slices.Equal`, `slices.Clone`, and `maps.Clone`.
   Preserve deep copying and nil versus explicit-zero semantics.
4. Consolidate repeated defaulting and fixture-loading code. Preserve timeout
   inheritance, declared list order, and deterministic serialization.
5. Add constants near their owning code for shared filter, file, header,
   resource, and fixture names. Prefer existing library constants. Keep
   test-only values in tests and YAML snippets readable.
6. Resolve lint findings. Keep any suppression narrow and explain its reason.
   Avoid abstractions that make a simple test or configuration harder to read.

### Tests

Create a concise inventory mapping each test or table case to its scenario,
expected result, and owning suite. For each removed case, identify surviving
coverage or explain why the case adds no useful protection.

| Layer | What it must prove |
| --- | --- |
| Configuration unit tests | Strict loading, defaults, validation, references, inheritance, and input immutability. |
| Golden checks | Complete generated Envoy and Kubernetes output remains correct. |
| Focused generation tests | Distinct variations or invariants, such as mapping-only updates leaving the bootstrap and Pod template unchanged. |
| Gateway e2e tests | Observable authentication, authorization, routing, request transformation, and update behavior. |
| Framework unit tests | Distinct infrastructure behavior needed for reliable e2e tests, such as ready-Pod selection and named target ports. |

- Consolidate overlapping defaults, immutability, and filter-order checks.
  The authentication validation table has identical "authorization without
  authentication" and "public server with authorization" cases.
- Replace YAML string replacement in `config/auth_test.go` and
  `config/jwks_test.go` with explicit snippets or fixtures. Use fresh typed
  configurations for generation variations.
- Assert the intended failure and relevant field, rather than accepting any
  error. Keep expected results independent of the implementation under test.
- Retain separate cases only when they prove different contracts. Unit and e2e
  coverage of one feature is useful when each detects a distinct failure.
- Keep `make update-golden` as explicit regeneration. Normal tests must not
  rewrite references. Review every golden diff.
- Use httpbin to check the backend method, path, headers, and body. Check that
  denied requests do not reach the backend.
- Retain routing, both JWT issuers, original-claim authorization, trusted header
  output, missing or unsafe attributes, mapping order and passthrough, TLS
  rotation, mapping reload, JWKS lifecycle, and metrics coverage.
- Keep use-case labels, isolated namespaces, `Ordered` Ginkgo containers,
  `BeforeAll` setup, `DeferCleanup`, and parallel-safe diagnostics.
- Keep Kubernetes lifecycle, forwarding, and diagnostics in the framework.
  Keep fixture shaping, protocol clients, and assertions in the e2e package.
- Test production settings through configuration and generation checks.
  Do not add gateway e2e tests for Envoy timeout, retry, HTTP/2 flow-control,
  overload, or draining semantics.

### Documentation

Consolidate documentation into these destinations:

| Document | Content |
| --- | --- |
| `README.md` | End-user guide: supported capabilities, a minimal generation example using the existing Go API, configuration examples, deployment requirements, updates, and telemetry. |
| `docs/envoy.md` | Technical explanation: generation, native filter order, claims versus working attributes, routing, TLS/JWKS trust, resource packaging, and reload behavior. |
| `CONTRIBUTING.md` | Local lint/test commands, golden regeneration, test ownership, and receiver placement rules. |

Merge useful content from `docs/jwt-auth.md`, `docs/tls-secrets.md`, and
`AUTH-PLAN.md` before removing those superseded documents. Update all links,
including the comment in `config.mtls.example.yaml`.

Use STE: short sentences, active voice, consistent terms, ASCII punctuation,
and direct instructions. Remove repetition, promotional material, implementation
history, and unsupported capability claims. Keep supported examples aligned with
the API. Explain certificate/mapping reloads and static configuration/CA rollouts.

## Validation and closeout

Run appropriate checks after each meaningful change and the complete checks
before handoff:

```sh
make test
make lint
go test -tags=e2e,envoyruntime -run '^$' ./...
go test -tags=e2e ./e2e/internal/framework
make e2e
git diff --check
```

For focused JWT development, use
`make -C e2e test GINKGO_ARGS='--label-filter=jwt'`.
Keep `make test-runtime` as optional pinned-image configuration validation.

The Kind suite needs Docker, Kind, Go, curl, and network access. It downloads
cmctl on first use and uses two Ginkgo processes by default. If the default Go
build cache is restricted, use `GOCACHE=/private/tmp/auth-gateway-go-cache`.

Check documentation links, supported examples, receiver placement, and the
absence of YAML string replacement in tests. Confirm the public API and
generated behavior remain stable.

Keep work on a feature branch and commit tested, reviewable steps with concise
messages. Never push directly to `main`. Update this handoff with completed
work, test consolidation decisions, actual check results, pending checks,
remaining issues, and any API recommendations.
