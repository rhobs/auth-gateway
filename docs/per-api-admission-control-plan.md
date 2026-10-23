# Restore admission control per API

## Goal

Loki failures must affect admission decisions for Loki requests only. Thanos
must keep its own success-rate history, even when both APIs share a hostname.

PR #9 fixed startup by removing AdmissionControl from route configuration,
which Envoy rejects. Its top-level replacement can couple APIs that share an
HTTP manager. Keep admission filters in the HTTP manager and put only policy
selection on routes.

## Implementation

- Remove the top-level `admission_control` field and restore
  `apis[].admission_control` with the current settings and `enabled: true`
  opt-in. Keep configuration version 1. Existing top-level configs require a
  manual move; add no alias or migration code.
- Update `github.com/envoyproxy/go-control-plane/envoy` to v1.39.0 for
  CompositePerRoute.
- In each HTTP manager, emit one native Envoy Composite filter with a named
  filter chain for each enabled API bound to that manager. Each chain contains
  its own AdmissionControl configuration.
- On each enabled API route, emit a direct CompositePerRoute whose
  `matcher.on_no_match` action selects that API's chain by name. Use the
  already matched route without duplicating path or method matching. Emit no
  selector for disabled APIs or generated 404/405 routes.
- Move the full example's active admission settings into `metrics-write`,
  `metrics-query`, and `logs`. Update the configuration reference and Envoy
  documentation, including the explicit Deployment rollout for bootstrap
  changes.

Do not put AdmissionControl itself in route configuration. Aliased admission
filters with route disable switches validated but allowed failure history to
leak between APIs. Per-cluster upstream admission filters isolate backend HTTP
errors, but share history across managers and do not account for connection
resets. The Composite design preserves downstream failure accounting.

## Verification

- Test loader acceptance of the API field and rejection of the removed
  top-level field, plus defaults and field-specific validation.
- Test named chains and route selectors for two enabled APIs sharing one HTTP
  manager, disabled APIs, multiple server bindings, and fallback routes.
  Assert every selector names an emitted chain.
- Update goldens and validate them with the pinned Envoy 1.39.1 image.
- Add runtime isolation tests in both failure directions for HTTP errors and
  connection resets. Prove rejected requests do not reach the backend.
- Run the required checks in [CONTRIBUTING.md](../CONTRIBUTING.md), including
  the full e2e suite. Submit from a feature branch through a PR.

## Assumptions

Admission histories are separate per API, HTTP manager, and Envoy worker.
Envoy's built-in admission monitoring counters may still be summed within an
HTTP manager; those counters do not drive admission decisions. Additional
per-API admission metrics are outside this change.
