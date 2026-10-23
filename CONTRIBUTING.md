# Contributing

Use Go 1.26 or later. The module targets Go 1.26 and pins golangci-lint
v2.14.0. `make tools` installs the pinned Ginkgo, lint, Kind, and cmctl tools.

## Pull requests

Develop feature and fix changes on a feature branch, then submit them to the
upstream repository through a pull request for review. Do not push directly to
`main`. Feature work is complete when it has passed review and is merged
upstream; local changes are for development and validation.

## Checks

Run checks relevant to the change. Before handoff, run the full e2e suite as
well:

```sh
make test
make lint
go test -tags=e2e,envoyruntime -run '^$' ./...
go test -tags=e2e ./e2e/internal/framework
make test-runtime
make e2e
```

`make test` runs unit tests and golden comparisons. `make lint` checks formatting,
tagged code, linters, and Markdown links. The tagged compile command does not
start a cluster. `make test-runtime` uses Docker to validate checked-in Envoy
goldens and exercise valid Envoy file reloads and per-API admission isolation.
`make e2e` runs the live Kind suite
and needs Docker, Go, and network access. It creates or reuses the
`auth-gateway-e2e` cluster and removes its test namespaces afterward. For
JWT-only iteration, run
`make -C e2e test GINKGO_ARGS='--label-filter=jwt'`; a filtered run does not
replace the full suite before handoff.

## Test ownership

| Location                           | Contract                                                                                          |
|------------------------------------|---------------------------------------------------------------------------------------------------|
| `config/*_test.go`                 | YAML loading, defaults, validation, Envoy and Kubernetes output, and generated references.        |
| `config/runtime*_test.go`          | Generated-file validation, valid file-based Envoy reloads, and per-API admission isolation.         |
| `e2e/internal/framework/*_test.go` | Reusable Kubernetes test infrastructure.                                                          |
| `e2e/*_test.go`                    | Observable routing, authentication, authorization, processing, TLS, reload, and metrics behavior. |

Give each test one contract and an observable result. Use valid baselines,
explicit YAML or fixtures, and independent expected values. For validation,
change one typed field and assert the expected error field or cause. Do not
build YAML through string replacement or use documentation examples as test
baselines.

E2E cases should assert the method, path, headers, and body received by
httpbin. Denied requests must not reach the backend. Keep scenarios isolated
and preserve cleanup and failure diagnostics. Keep Envoy-only behavior such as
timeouts, retries, overload, and flow control out of gateway e2e tests.

## Golden files

Tests compare generated output with checked-in references; they do not update
them. For an intentional output change, run:

```sh
make update-golden
git diff -- config/testdata
make test
git diff --check
```

Review every changed reference. Do not regenerate goldens to hide an unexpected
output change.
