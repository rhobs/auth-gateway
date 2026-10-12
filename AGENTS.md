# Repository agent guidance

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for checks, test ownership, and
golden-file updates.

## Scope and architecture

- Treat the checked-in version 1 configuration schema as the supported
  contract. Do not add aliases or migration code unless the task asks for it.
- Keep configuration, the single full `config.example.yaml`, documentation,
  generated output, and tests aligned.
- Client-certificate mTLS is unsupported. Do not implement it unless the task
  changes scope.
- Keep JWT verification, API-key authentication, authorization, and attribute
  mapping in native Envoy filters. Lua is limited to per-API response counters.
- Put mapped-attribute processing in `processing.yaml`, loaded through ECDS
  from a separate `<name>-processing` ConfigMap. Mapping updates change only
  that ConfigMap and do not change the bootstrap, Deployment template, or Pod
  identity.
- Static bootstrap changes require an explicit Deployment rollout. Generated
  Deployments have no checksum annotation.
- Keep reusable Kubernetes lifecycle, port forwarding, readiness, and
  diagnostics in `e2e/internal/framework`. Keep fixtures, protocol clients, and
  scenario assertions in the e2e package.

## Go style

- Use one receiver style for all methods on a type. If a method needs a pointer
  receiver, use pointer receivers for every method on that type.

## Tests

- Keep each test focused on one behavior. Use valid baselines and assert the
  expected error field or cause for invalid configuration.
- Use explicit YAML or checked-in fixtures for loader tests. Do not construct
  test YAML with string replacement. For semantic validation, load a valid
  baseline and mutate one typed field.
- Keep tests independent of documentation examples. Use test-owned fixtures
  instead of loading `config.example.yaml`.
- Unit tests cover schema, defaults, validation, and generated output. Gateway
  e2e tests cover observable behavior. Do not use gateway e2e tests for Envoy
  semantics such as flow control, timeouts, retries, overload, or draining.
- Test JWKS cache settings in generated configuration. Keep cache lifecycle
  behavior out of gateway e2e tests.
- Keep API-key request decisions read-only on a fresh shared gateway. Use Kind
  for one projected Secret rotation and the runtime suite for valid file-based
  ECDS/SDS reloads and empty-key revocation. Do not test native Envoy rejection
  or retention of malformed updates.
- Isolate e2e scenarios by use case and clean up their namespaces. Verify
  forwarding through httpbin, including method, path, headers, and body. Show
  that denied requests do not reach the backend.
- Run relevant checks and the full e2e suite before handoff. Runtime-image
  checks are optional when the change does not require them.
- Run authorized Docker-backed e2e and runtime checks with escalated sandbox
  permissions on the initial call. If a sandbox denial occurs, retry with
  escalation without asking the user to repeat authorization.

## Documentation and workflow

- Keep [docs/configuration-reference.md](docs/configuration-reference.md)
  aligned with the schema and example.
- Keep user guides focused on configuration, client requests, observable
  behavior, and required external resources. Technical docs should explain
  Envoy behavior, not Go function names or code structure.
- Work on a feature branch. Never push directly to `main`; keep changes local
  and do not open a PR or MR unless asked.
- Use concise, natural-language commit messages without emojis.
