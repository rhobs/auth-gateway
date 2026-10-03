# Production configuration implementation evidence

The implementation follows [the production plan](production-configuration-plan.md).
Verification covers our defaults, validation, generated resources and lifecycle
helper. Production capacity and Envoy HTTP behavior belong to deployment testing;
no new production e2e scenarios are included.
Jira MCP and the Jira CLI were unavailable in this session; scope came from the
checked-in plan and handover. No Jira issue was changed.

## JWKS and trust

- Added `jwt.jwks`, duration validation, per-provider transport/cache/breaker
  settings, CA sources and deterministic ConfigMap mounts. The legacy
  `jwks_uri` key is rejected. Certificates now require a matching DNS or IP SAN.
- JWT fixtures use supported input settings. Cache rewriting and the mounted
  replacement of the system CA file have been removed.
- Unit tests, `go vet ./...`, e2e compilation and generated reference outputs
  pass. Existing JWT cases retain their schema and CA mount adaptations.
- Runtime: Envoy `v1.39.1`, local Linux arm64 image digest
  `sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4`.
  Go bindings remain `v1.37.0`.
- The fixed request-control filter also removes the pinned router's stream
  duration, alternate timeout response and retriable status/header controls.

## Request and cluster controls

- Unit tests cover listener limits on every chain, route timeout inheritance,
  HTTP protocol settings, TLS identities, shared CA mounts and immutable inputs.
- The auth example comments out defaults. A unit test loads it and checks every
  default and resolved route timer.
- Optional `make test-runtime` validates generated files with Envoy
  `--mode validate` and validates the collector configuration. All eight fixture
  outputs pass on the pinned images. This checks configuration compatibility;
  it does not send requests through Envoy.
