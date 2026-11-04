# Fault injection

Fault injection returns configured HTTP errors after authentication,
authorization, and request-header validation. It supports an exact request
header trigger and selectors for authenticated attributes such as a tenant
ID. Status and percentage stay under operator control.

For an API that already requires authentication, configure these fields:

```yaml
metrics:
  labels:
    tenant: tenant_id
fault_injection:
  enabled: true
  match:
    headers:
      X-Inject-Fault: "true"
    attributes:
      tenant_id: [test-tenant]
  abort:
    http_status: 503
    percentage: 100
```

Here `tenant_id` must be declared by a bound authenticator using a verified
JWT claim, API-key credential attribute, or certificate SAN. A client-supplied
tenant header cannot replace that identity value. Header sources are rejected
for attribute selectors.

Regenerate and apply the gateway resources, then explicitly roll out the
Deployment. For example, a request authenticated as `test-tenant` with
`X-Inject-Fault: true` now returns `503`. The same tenant without that header,
or another tenant with the header, continues normally. Requests that fail
authentication or authorization keep their usual denial status. All configured
headers and attributes must match; values within an attribute list are
alternatives. Missing attributes do not match.

Omitting `match` makes every request that passes authentication, authorization,
and required-header checks eligible. A percentage below `100` samples only
matching requests. Omit `fault_injection` or set `enabled: false` to disable
it, then regenerate, apply, and roll out again. See the
[configuration reference](configuration-reference.md#fault-injection) for
field constraints.

## SLO accounting

An injected reply is local to the gateway and never reaches the backend. With
`metrics` configured, the exported per-API counter includes:

```text
auth_gateway_http_requests_total{api="write",http_status_code="503",fault_injected="true",tenant="test-tenant"}
```

The name above is the default; use your `observability.metrics.custom_metric_name`
if configured. Real backend replies, authentication denials, and other gateway
responses have `fault_injected="false"`. The marker comes from native fault
metadata, so a backend `503` or a spoofed request header does not mark a reply
as injected. Ensure the Collector endpoint is scraped by the SLO monitoring
system.

For an SLO based on upstream responses, add the injected subset to the total
response count and to the error count when its status matches the SLO's error
definition. For a `5xx` SLO, use an injected status such as `503`.

| Response | Upstream responses | Injected responses | SLO responses | SLO errors (`5xx`) |
|----------|--------------------|--------------------|---------------|-------------------|
| Backend `200` | 1 | 0 | 1 | 0 |
| Backend `503` | 1 | 0 | 1 | 1 |
| Injected `503` | 0 | 1 | 1 | 1 |
| Authentication `401` | 0 | 0 | 0 | 0 |
| Authorization `403` | 0 | 0 | 0 | 0 |

Keep the existing upstream rate expression and normalize its output to labels
`api`, `tenant`, and `http_status_code`. In this example that existing recording
rule is named `upstream:http_responses:rate5m`. Use the same API and tenant
values in both sources. If the existing SLO has no tenant dimension, omit
`tenant` from the aggregations. If it excludes particular status codes from
the denominator, apply the same selection to injected responses.

Add these rules to the monitoring system that owns the SLO:

```yaml
groups:
  - name: auth-gateway-slo
    rules:
      - record: auth_gateway:fault_injected_responses:rate5m
        expr: |
          sum by (api, tenant, http_status_code) (
            rate(auth_gateway_http_requests_total{fault_injected="true"}[5m])
          )
      - record: slo:http_responses:rate5m
        expr: |
          sum by (api, tenant, http_status_code) (
            {__name__=~"upstream:http_responses:rate5m|auth_gateway:fault_injected_responses:rate5m"}
          )
```

Selecting both recording series and summing them handles tenants that have
only upstream responses or only injected responses. Filtering the gateway
input to `fault_injected="true"` counts each injected response once and keeps
authentication denials outside the upstream SLO.

For example, the `5xx` error ratio becomes:

```promql
(
  sum by (api, tenant) (slo:http_responses:rate5m{http_status_code=~"5.."})
  or on (api, tenant)
  (0 * sum by (api, tenant) (slo:http_responses:rate5m))
)
/
sum by (api, tenant) (slo:http_responses:rate5m)
```

This requires updating the SLO recording rules or queries. Backend response
counters and Envoy's native upstream counters continue to describe actual
upstream traffic and cannot include requests aborted before forwarding.
