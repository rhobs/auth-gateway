# Contributing

Use Go `1.26.0` or later. The module targets Go 1.26. The lint tool is pinned
to golangci-lint `v2.14.0` in `go.mod`. E2E tools are pinned with Go's tool
directive in their module files. `make tools` fetches and builds the pinned
Ginkgo, lint, Kind, and cmctl tools. Individual Makefile targets also build
the tools they use on first run.

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
`make test-runtime` validates generated files with Envoy and exercises live file-based reloads with Envoy and httpbin; it needs Docker.
`make e2e` runs the live Kind suite.

The live end-to-end (e2e) suite needs Docker with a reachable daemon, Go, Python 3.10 or later, and network access.
The Makefile builds Kind `v0.30.0` and cmctl `v2.6.1` through `go tool` on
first use, creates or reuses the `auth-gateway-e2e` cluster, and uses two
Ginkgo processes by default.
It removes the test namespaces when it finishes.
Reports go to `e2e/.state/reports/<run-id>`; scenario diagnostics use the framework's context-specific state directory. Each report directory contains `auth-gateway.json` and `timings.json`. The timing sidecar records image-default generation, cmctl setup, cluster and image setup, framework tests, e2e compilation, and Ginkgo CLI wall time. CI uploads the reports even when a test step fails.

Summarize selected runs with:

```sh
python3 scripts/summarize-ginkgo-report.py \
  e2e/.state/reports/run-one/auth-gateway.json \
  e2e/.state/reports/run-two/auth-gateway.json \
  e2e/.state/reports/run-three/auth-gateway.json
```

The summary lists every reported spec and container, marks the first and last spec in each container, and reports hook costs from Ginkgo events. Per-spec `RunTime` includes Ginkgo hooks. Phase rows appear for marked mutable operations such as Secret and ECDS reloads, resets, SDS rotations, and the bootstrap rollout. A failed phase may have an unmatched start marker and is reported as incomplete. Reports without `timings.json` can still be summarized, but Make stage timings are unavailable. Compare three warm runs by median and range, and measure a cold-cluster run separately.

The cert-manager case times its renewal request and the interval until Envoy serves the renewed certificate. The controller's Secret write is internal to cert-manager, so it cannot be timed separately. The bootstrap inactive-behavior phase includes its existing request checks and 60-second observation period; it is kept intact to preserve the rollout assertion.

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

| Suite | Owns |
| --- | --- |
| `config/config_test.go`, `config/servers_test.go`, `config/auth_test.go`, `config/duration_test.go` | Strict YAML loading, defaults, schema and semantic validation, timeout inheritance, duration serialization, and input immutability. |
| `config/api_keys_test.go` | API-key credential loading and validation, generated Secret resources, and key authentication behavior. |
| `config/cel_test.go`, `config/generate_test.go` | Generated Envoy expressions, filters, routes, authorization policies, and reference output. |
| `config/kubernetes_test.go`, `config/observability_test.go` | Kubernetes packaging and observability defaults, validation, and generated resources. |
| `config/runtime*_test.go` | Validation of generated files and live file-based reload behavior with pinned Envoy and httpbin images. |
| `config/example_test.go` | Compiled consumer examples for loading configuration and generating files and resources. |
| `e2e/internal/framework/*_test.go` | Infrastructure behavior needed by e2e tests, including ready-Pod choice and named target-port resolution. |
| `e2e/*_test.go` | Observable gateway behavior: routing, authentication, authorization, request transformation, TLS rotation, mapping reload, and metrics. |

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
