# Repository agent guidance

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for local checks, code layout, and golden-file updates.

## Scope and compatibility

- Treat the checked-in configuration schema as the supported contract. Do not add aliases, migration code, or dedicated tests for obsolete formats unless a task explicitly requires them.
- Keep configuration changes, examples, documentation, generated Envoy and Kubernetes resources, and tests aligned.
- Take some inspiration from the PoC that started this project /Users/pgough/Desktop/projects/regional-observability-service but dont rely on it for code quality etc.
- 
- mTLS remains future work. Do not implement it until the task scope changes. Keep `config.mtls.example.yaml` as an example.

## Architecture

- Keep JWT handling in native Envoy filters. Do not reintroduce Lua if possible.
- Put mapped-claim processing in `processing.yaml`, loaded through ECDS from a separate `<name>-processing` ConfigMap. Mapping updates should change only that ConfigMap and leave the bootstrap, Deployment template, and Pod identity unchanged.
- Static bootstrap changes require an explicit Deployment rollout. There is no checksum annotation; document this behavior when relevant.
- Keep reusable Kubernetes lifecycle, port-forwarding, readiness, and diagnostics in `e2e/internal/framework`. Keep fixture shaping, protocol-specific clients, and scenario assertions in the e2e test package.

## Testing

- Keep each test focused on a distinct behavior. Use valid baselines and assert the intended error field or cause for invalid configuration.
- Use explicit YAML snippets or checked-in fixtures for loader tests. Do not build YAML through string replacement. For semantic validation tests, load a valid baseline and mutate one typed field so each case exercises `Validate()` without repeating YAML.
- Unit tests cover schema, defaults, validation, and generated output. Gateway e2e tests cover observable gateway behavior. Do not add gateway e2e tests for Envoy semantics such as HTTP/2 flow control, timeouts, retries, overload, or connection draining.
- Organize e2e scenarios by use case with isolated namespaces and cleanup. Verify forwarding through httpbin, including method, path, headers, and body. Denied requests must not reach the backend.
- Run checks relevant to the change and the full e2e suite before handoff. Runtime-image checks are optional when they are not required by the change.

## Workflow

- Work on a feature branch and never push directly to `main`.
- Keep work local for now. Do not push branches or open PRs/MRs until asked.
- Keep documentation brief and use simple technical English.
- Keep user-facing doc guides focused on gateway configuration, client
  requests, observable behavior, and resources users must provide.
- Docs in docs/guides should provide user facing documentation and doesn't need to focus on envoy internals
- We can create technical documentation elsewhere, but we should never discuss function names etc. It should focus on how envoy behaves rather than current implementation of code at a function level.
- Use concise, natural-language commit messages without emojis.
