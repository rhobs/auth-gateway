# Envoy resource update monitoring

Production monitoring is configured outside this library. The pinned Envoy
image exposes these update-failure counters at `/stats/prometheus`:

- `envoy_extension_config_discovery_http_filter_envoy_filters_http_set_filter_state_update_failure`
- `envoy_extension_config_discovery_http_filter_envoy_filters_http_api_key_auth_update_failure`
- `envoy_sds_update_failure`

The generated Collector scrapes the counters and exposes them at `/metrics`.
The SDS counter includes `envoy_xds_resource_name`; the ECDS counters do not
identify a resource. Confirm that production Prometheus preserves the gateway
cluster, namespace, and Pod labels.

Alert when a counter increases, for example with
`increase(<counter>[5m]) > 0`. The runbook should explain that Envoy keeps the
last accepted resource after a failed update. Operators should fix the input
and apply a valid update. To revoke API keys, apply a valid empty credential
list; deleting or corrupting the Secret is not a revocation method.
