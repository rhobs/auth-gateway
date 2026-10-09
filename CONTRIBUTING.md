# Contributing

Use Go `1.26.0` or later. The module targets Go 1.26. The lint tool is pinned to golangci-lint `v2.14.0` in `go.mod`. E2E tools are pinned with Go's tool directive in their module files.

## Local checks

Run the checks relevant to your change:

```sh
make test
make lint
go test -tags=e2e,envoyruntime -run '^$' ./...
go test -tags=e2e ./e2e/internal/framework
make test-runtime
make e2e
```

`make test` runs unit tests and golden comparisons.
`make lint` checks formatting and runs the configured linters across normal and tagged code.
The tagged compile command checks e2e and runtime-only packages without starting a cluster.
The framework command runs Kubernetes helper tests.
`make test-runtime` validates generated configuration with the pinned runtime images.
`make e2e` runs the live Kind suite.


The live end-to-end (e2e) suite needs Docker with a reachable daemon, Kind, Go, and network access.
It builds cmctl `v2.6.1` on first use, creates or reuses the `auth-gateway-e2e` cluster, and uses two Ginkgo processes by default.
It removes the test namespaces when it finishes.
Reports go to `e2e/.state/reports`; scenario diagnostics use the framework's context-specific state directory.

For JWT-only iteration, run:

```sh
make -C e2e test GINKGO_ARGS='--label-filter=jwt'
```

The labels select scenarios; they do not replace the full suite before handoff. Compilation and generated configuration checks do not prove live Envoy behavior.

## Code organization

Follow current project conventions and idiomatic Go.

Put constants beside the code that owns them if possible.
Keep test-only names in the test package.
Avoid sharing expectation constants with code under test when that would make both sides depend on the same value.
Comments should be short and explain behavior that is not clear from the code.

## Test ownership

| Suite                                                                                          | Owns                                                                                                                                                    |
|------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `config/config_test.go`, `defaults_test.go`, `servers_test.go`, `auth_test.go`, `jwks_test.go` | Strict YAML loading, defaults, validation, references, TLS trust, timeout inheritance, and input immutability.                                          |
| `config/generate_test.go`, `jwt_generate_test.go`, `kubernetes_test.go`                        | Generated Envoy behavior, conditional filter order, complete reference output, Kubernetes packaging, ports, mounts, and reload boundaries.              |
| `e2e/internal/framework/*_test.go`                                                             | Infrastructure behavior needed by e2e tests, including ready-Pod choice and named target-port resolution.                                               |
| `e2e/*_test.go`                                                                                | Observable gateway behavior: routing, authentication, authorization, request transformation, TLS rotation, mapping reload, JWKS lifecycle, and metrics. |

Give each test a distinct contract and an observable expected result. Use a valid baseline and change one property for validation cases. Assert the expected error field or cause. Use fresh typed configurations for generation variants. Keep YAML inputs explicit; do not create test configurations with string replacement. Use independent expected values for generated structures.

E2e cases should verify requests with httpbin, including the method, path, headers, and body that reach the backend. Denied requests must be shown not to reach the backend. Keep scenarios isolated in their own namespaces and preserve cleanup and failure diagnostics.

## Golden files

Normal tests compare generated output with checked-in references and never update them. When an intentional output change needs new references, run:

```sh
make update-golden
git diff -- config/testdata
make test
git diff --check
```

Review each changed reference file. Do not regenerate goldens to hide an unexpected output change.
