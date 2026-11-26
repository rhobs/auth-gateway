# Traffic protection

These controls limit work sent to backends and protect the gateway when
resources are under pressure. They use native Envoy features.

| Control                                     | Purpose                                                    | Configuration                                      |
|---------------------------------------------|------------------------------------------------------------|----------------------------------------------------|
| [Circuit breakers](#circuit-breakers)       | Bound upstream connections and requests.                   | `apis[].circuit_breakers`                          |
| [Admission control](#admission-control)     | Shed traffic when an API's success rate falls.             | `apis[].admission_control`                         |
| [Overload protection](#overload-protection) | Protect Envoy's memory and downstream connection capacity. | `overload`                                         |
| [Timeouts](#timeouts)                       | Bound connection and request lifetimes.                    | `listener`, `apis[].timeouts`, and route overrides |

See the [full configuration example](../config.example.yaml) for settings in
context. Changes require regenerating and applying the configuration, followed
by an explicit Envoy Deployment rollout when using Kubernetes.

## Circuit breakers

Circuit breakers limit connections, pending requests, active requests, and
active retries for an upstream cluster. Configure an API's limits under
`apis[].circuit_breakers`. JWT key fetching has separate limits under
`authenticators[].jwt.jwks.circuit_breakers`.

The gateway applies defaults even when the block is omitted: `1024`
connections, `1024` pending requests, `1024` active requests, and `0` active
retries. Limits apply independently in each Envoy process. Separate APIs have
separate upstream clusters, including when they point to the same backend.

See the [gateway fields and defaults](configuration-reference.md#circuit-breakers)
and [Envoy circuit breaking](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/upstream/circuit_breaking)
for limit behavior and overflow counters.

## Admission control

Enable `apis[].admission_control.enabled` to reject a proportion of requests
when an API's recent success rate falls below its configured threshold.
Sampling window, minimum request rate, and maximum rejection probability
control when and how much traffic is shed. Admission control is disabled by
default.

Histories are separate per API, HTTP connection manager, and Envoy worker.
Rejected requests return `503`, never reach the backend, and do not count as
upstream failures in that history.

See the [gateway settings](configuration-reference.md#admission-control),
[gateway filter behavior](envoy.md#per-api-admission-control), and
[Envoy admission control](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/http/http_filters/admission_control_filter)
for the success-rate calculation and filter statistics.

## Overload protection

Top-level `overload` protects the Envoy process using a heap budget and a cap
on downstream connections. Both limits are required when enabling it;
omitting the block leaves overload protection disabled.

Under heap pressure, Envoy attempts to release free memory and then rejects
new requests with `503` at the configured thresholds. The heap budget must be
below the Envoy container's memory limit when generating Kubernetes resources.

See the [gateway settings](configuration-reference.md#overload-protection) and
[Envoy overload manager](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/operations/overload_manager/overload_manager)
for resource monitors and overload actions.

## Timeouts

Listener settings bound client header receipt, request receipt, and idle
connections. An upstream's `connect_timeout` bounds connection establishment.
API and route `timeouts` control individual requests:

- `response_timeout` bounds the wait for a complete upstream response after the
  client's request has been received.
- `idle_timeout` bounds periods without stream activity.
- `max_stream_duration` bounds the total stream lifetime.

Route values override API values independently for each field. The gateway's
response timeout defaults to `30s`; idle and maximum stream duration defaults
come from the listener. A response timeout cannot exceed the effective maximum
stream duration. Configured durations must be positive.

See [listener settings](configuration-reference.md#node-and-listener),
[route timeout settings](configuration-reference.md#route-timeouts), and
[Envoy timeouts](https://www.envoyproxy.io/docs/envoy/v1.39.1/faq/configuration/timeouts)
for the scope of each timer.
