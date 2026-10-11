# Repository agent guidance

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for local checks, code layout, and golden-file updates.

## Scope and compatibility

- Treat the checked-in configuration schema as the supported contract. Do not add aliases, migration code, or dedicated tests for obsolete formats unless a task explicitly requires them.
- Keep configuration changes, examples, documentation, generated Envoy and Kubernetes resources, and tests aligned.
- Use the original prototype as context when useful; follow this repository's current code and quality standards.
- mTLS remains future work. Do not implement it until the task scope changes. Keep `config.mtls.example.yaml` as an example.

## Architecture

- Keep JWT verification, API-key authentication, authorization, and attribute mapping in native Envoy filters. Keep Lua limited to per-API response counters. Envoy's built-in HTTP stats cannot currently combine route metadata, final downstream status (including authentication and RBAC local replies), and processed filter-state values in one counter. Do not use Lua to implement those behaviors.
- Put mapped-claim processing in `processing.yaml`, loaded through ECDS from a separate `<name>-processing` ConfigMap. Mapping updates should change only that ConfigMap and leave the bootstrap, Deployment template, and Pod identity unchanged.
- Static bootstrap changes require an explicit Deployment rollout. There is no checksum annotation; document this behavior when relevant.
- Keep reusable Kubernetes lifecycle, port-forwarding, readiness, and diagnostics in `e2e/internal/framework`. Keep fixture shaping, protocol-specific clients, and scenario assertions in the e2e test package.

## Go style

- Use one receiver style for every method on a type. If one method needs a pointer receiver, such as a mutating YAML unmarshaller, use pointer receivers for all methods on that type.

## Testing

- Keep each test focused on a distinct behavior. Use valid baselines and assert the intended error field or cause for invalid configuration.
- Use explicit YAML snippets or checked-in fixtures for loader tests. Do not build YAML through string replacement. For semantic validation tests, load a valid baseline and mutate one typed field so each case exercises `Validate()` without repeating YAML.
- Unit tests cover schema, defaults, validation, and generated output. Gateway e2e tests cover observable gateway behavior. Do not add gateway e2e tests for Envoy semantics such as HTTP/2 flow control, timeouts, retries, overload, or connection draining.
- Keep JWKS caching checks in unit tests: assert that configuration produces the intended Envoy cache duration. Do not test JWKS caching behavior in gateway e2e, including warm or cold caches, expiry, and outage masking. Keep JWT e2e tests focused on authentication and authorization outcomes.
- Keep API-key request decision cases read-only on a fresh shared gateway. Test Secret rotation, malformed-update retention, recovery, and revocation as one lifecycle progression instead of resetting state between transitions.
- Organize e2e scenarios by use case with isolated namespaces and cleanup. Verify forwarding through httpbin, including method, path, headers, and body. Denied requests must not reach the backend.
- Run checks relevant to the change and the full e2e suite before handoff. Runtime-image checks are optional when they are not required by the change.

## Workflow

- Work on a feature branch and never push directly to `main`.
- Keep work local for now. Do not push branches or open PRs/MRs until asked.
- Keep documentation brief and use simple technical English.
- Maintain [docs/schema-test-ledger.md](docs/schema-test-ledger.md) as the long-term coverage reference for supported configuration fields. Update it when the schema, behavior, or test evidence changes. Treat [docs/test-suite-review.md](docs/test-suite-review.md) as a dated worklist and benchmark; retire or replace it when its phases are resolved.
- Keep user-facing doc guides focused on gateway configuration, client
  requests, observable behavior, and resources users must provide.
- Docs in docs/guides should provide user facing documentation and doesn't need to focus on envoy internals
- We can create technical documentation elsewhere, but we should never discuss function names etc. It should focus on how envoy behaves rather than current implementation of code at a function level.
- Use concise, natural-language commit messages without emojis.
- Ensure docs/configuration-reference.md is up to date with the checked-in schema and examples.
