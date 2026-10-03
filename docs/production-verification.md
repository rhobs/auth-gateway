# Production configuration implementation evidence

The implementation follows [the production plan](production-configuration-plan.md).
These are local functional checks, not production capacity recommendations.
Jira MCP and the Jira CLI were unavailable in this session; scope came from the
checked-in plan and handover. No Jira issue was changed.

## JWKS and trust

- Added `jwt.jwks`, duration validation, per-provider transport/cache/breaker
  settings, CA sources and deterministic ConfigMap mounts. The legacy
  `jwks_uri` key is rejected. Certificates now require a matching DNS or IP SAN.
- JWT fixtures use supported input settings. Cache rewriting and the mounted
  replacement of the system CA file have been removed.
- Unit tests, `go vet ./...`, e2e compilation, generated reference outputs and
  whitespace checks pass. The focused JWT Kind suite passes all 11 specs on two
  Ginkgo processes, including sustained-outage cache expiry, recovery without
  Pod replacement, cold-cache failure, wrong-host and untrusted-root failures,
  and the existing mapping-only ECDS update.
- Runtime: Envoy `v1.39.1`, local Linux arm64 image digest
  `sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4`.
  Go bindings remain `v1.37.0`.
- Pinned router source also reads `x-envoy-upstream-stream-duration-ms` and
  `x-envoy-upstream-rq-timeout-alt-response`. The request-control protection
  must cover these in addition to the original plan's list.
