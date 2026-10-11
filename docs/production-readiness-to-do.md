# Production readiness to do

Track operational follow-ups that need deployment or monitoring-system changes
outside the gateway configuration library.

## Alert on Envoy resource update failures

Add a warning-level alert for increases in Envoy's native resource update
counters. The pinned Envoy image exposes these counters at
`/stats/prometheus`:

- `envoy_extension_config_discovery_http_filter_envoy_filters_http_set_filter_state_update_failure`
- `envoy_extension_config_discovery_http_filter_envoy_filters_http_api_key_auth_update_failure`
- `envoy_sds_update_failure`

The generated Collector config in
[`playground/generated/otel-collector.yaml`](../playground/generated/otel-collector.yaml)
scrapes that endpoint and forwards the counters from its `/metrics` endpoint.
The SDS counter includes `envoy_xds_resource_name`; the ECDS counters do not
identify a resource. Group alerts by the gateway's cluster, namespace, and Pod
labels supplied by the production metrics pipeline.

The alert should fire when any counter increases during a short window, for
example when `increase(<counter>[5m]) > 0`. Confirm that production Prometheus
scrapes the Collector Service and preserves the counter names and target labels
before enabling the rule.

The runbook should explain that Envoy keeps the last accepted resource after a
failed update. Operators should fix the source input, regenerate it with the
library helpers where applicable, and apply a valid update. Deleting an
API-key Secret is not the revocation procedure; an empty valid credential list
revokes all keys.

Acceptance: the three counters are visible in production Prometheus, an
increase raises the alert with gateway identity, and the runbook describes
recovery and API-key revocation.
