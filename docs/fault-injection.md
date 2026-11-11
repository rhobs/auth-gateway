# Fault injection

Fault injection returns configured HTTP errors after authentication,
authorization, and request-header validation. It supports request header
conditions and selectors for verified attributes such as a tenant ID. Status
and percentage stay under operator control.

For an API that already requires authentication, configure the fault on its
server binding. Each server can set a different policy for the same API:

```yaml
servers:
- hostname: metrics.example.com
  apis:
  - name: write
    fault_injection:
      enabled: true
      match:
        headers:
        - name: X-Inject-Fault
          expression: equals
          value: "true"
        attributes:
        - name: tenant_id
          expression: in
          value: [test-tenant]
      abort:
        http_status: 503
        percentage: 100
    access: # existing access entries
    - name: default
      # existing authentication and authorization settings
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
headers and attributes must match; values in an `in` list are alternatives.
`equals`, `in`, and `present` are supported. `present` requires the header to
exist or the verified attribute to have a nonempty value. Missing attributes
do not match.

Omitting `match` makes every request that passes authentication, authorization,
and required-header checks eligible. A percentage below `100` samples only
matching requests. Omit `fault_injection` or set `enabled: false` to disable
it, then regenerate, apply, and roll out again. See the
[configuration reference](configuration-reference.md#fault-injection) for
field constraints.

## SLO accounting

With `metrics` configured, an injected reply counts once in the standard
per-API request counter, using its configured status and authenticated labels:

```text
auth_gateway_http_requests_total{api="write",http_status_code="503",tenant="test-tenant"}
```

A backend `503` and an injected `503` with the same labels increment the same
series. Use this counter for both SLO request totals and status-based
error counts. The calculation stays the same whether injection is enabled or
disabled. There is no additional metric, label, or recording rule for faults.

The name above is the default; use `observability.metrics.custom_metric_name`
if configured. Ensure the Collector endpoint is scraped by the SLO monitoring
system. The counter also includes authentication and authorization denials,
using their usual status codes.

Injected requests never reach the backend. Backend response counters and
Envoy's native upstream counters measure forwarded traffic only; use the
gateway request counter for an SLO that includes local replies.
