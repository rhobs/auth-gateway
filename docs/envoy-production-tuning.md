# Envoy production tuning for high-throughput deployments

This guide reviews Envoy controls that can matter in production systems
handling high request rates. It maps them to the current auth-gateway
generator and uses the Thanos and Loki routes in
[the example config](../config.example.yaml) as workload context.

Treat the values below as a baseline to measure, not as recommended capacity
limits. Choose production values from representative traffic, latency
objectives, and backend behavior.

## Current gateway baseline

- Every API cluster gets circuit breaker limits of 1,024 connections,
  pending requests, and active requests, with concurrent retries capped at 0.
  These are generated defaults and can be overridden per API. The limits
  apply within each Envoy process, so increasing replicas also increases
  aggregate upstream capacity. A retry breaker limit does not create a retry
  policy. See [the defaults](../config/config.go) and
[cluster generation](../config/generate.go).
- The HTTP connection manager allows 32 KiB of request headers, waits up to
  5 seconds for request headers, and sets 60-second idle timeouts. Request,
  route, and maximum stream durations are 30 seconds; upstream connection
  establishment is limited to 5 seconds.
- The downstream listener and each upstream cluster have a 1 MiB
  per-connection buffer limit. This is a buffer cap, not a body-size limit.
- Upstream clusters use strict DNS and have no explicit load-balancer policy,
  HTTP protocol override, TLS transport socket, health check, outlier
  detection, or route retry policy. No overload manager is generated. The
  HTTP filter chain currently contains the router.
- HTTPS is optional. When configured, downstream TLS allows TLS 1.2 and 1.3
  and advertises `h2` and `http/1.1`. Upstream connections are currently
  plaintext.
- Envoy's admin endpoint binds to `127.0.0.1:9901`. The OpenTelemetry
  Collector scrapes stats every 30 seconds. Envoy writes structured access
  logs for responses with status 400 or higher.
- Kubernetes output defaults to two replicas, a 50m CPU request, a 1 CPU
  limit, a 64 MiB memory request, and a 256 MiB memory limit for Envoy. The
  readiness probe is TCP-based, the termination grace period is 30 seconds,
  and the generated Envoy arguments do not set worker concurrency. These are
  deployment defaults, not performance targets. See
[Kubernetes generation](../config/kubernetes.go).

The route mix matters: metrics writes and Loki OTLP are POST operations,
while Thanos query endpoints allow GET and POST. Query requests can have
different duration and resource needs from telemetry writes.

## Controls to evaluate

### Evaluate first

- **Worker concurrency and CPU sizing.** Envoy's worker count affects how
  much work one process can handle. The generated container does not set
  `--concurrency`; measure the count Envoy selects in the target container
  and compare it with its CPU quota, throttling, and request load. Size CPU
  requests and limits from load measurements before adding a fixed
  worker-count setting.
- **Process-level overload protection.** Envoy's overload manager can
  monitor process or cgroup resource pressure and apply load-shedding actions
  before the process runs out of memory. This covers pressure across
  listeners and clusters, while circuit breakers cover individual upstream
  clusters. Evaluate it with the 1 MiB connection buffer caps and actual
  memory limit; do not derive thresholds from the limit alone.
- **Route-specific timeouts and request bounds.** The shared 30-second
  request, route, and stream limits may fit short writes but constrain slow
  queries or large uploads. Measure each route and expose timeout controls at
  the narrowest useful scope. If a body-size limit is needed, use a mechanism
  that matches the payload pattern; a buffering filter holds request data in
  memory and can be a poor fit for large or streaming writes.
- **Capacity and latency metrics.** Track request latency by route, upstream
  active and pending requests, connection counts, timeouts, retries, circuit
  breaker overflow, CPU throttling, and Envoy memory. Keep metric labels
  bounded. The current 30-second scrape is a starting point; set the interval
  to meet alerting needs without creating unnecessary scrape load.

### Depends on backend topology and protocol support

- **Upstream HTTP/2 and connection pools.** HTTP/2 can multiplex concurrent
  requests over fewer upstream connections and is required for gRPC. It needs
  backend support and appropriate stream and flow-control limits. Benchmark
  it with Thanos and Loki before enabling it; multiplexing can also
  concentrate concurrent work on fewer connections. Downstream TLS already
  advertises HTTP/2 when HTTPS is configured.
- **Load balancing, health checks, and outlier detection.** With no explicit
  policy, Envoy uses its default round-robin policy. Least-request balancing
  can help when Envoy sees multiple hosts and request costs vary. Active
  health checks and outlier detection also need Envoy to see individual
  endpoints. A normal Kubernetes Service name commonly resolves to a
  Service IP, where Kubernetes handles pod selection and readiness; Envoy
  cannot eject an individual pod behind that IP. Headless service DNS or
  endpoint discovery can give Envoy per-endpoint visibility.
- **Endpoint discovery and locality.** Static clusters with DNS are simple
  for a small, stable upstream list. If backend membership changes frequently
  or Envoy must balance across many pods or zones, evaluate endpoint
  discovery and locality-aware balancing. This requires an endpoint source
  and zone metadata; it is an architecture change as well as an Envoy
  setting.
- **Upstream TLS.** Configure TLS transport sockets with trusted certificates
  and hostname validation when traffic crosses a trust boundary. Use client
  certificates when upstream mTLS is required. The current downstream TLS
  configuration does not secure Envoy-to-backend connections.

### Enable only for a defined traffic policy

- **Retries and retry budgets.** There is no route retry policy today, and
  the concurrent retry breaker is zero. A retry policy should bound attempts
  and per-try time, fit inside the overall route deadline, and account for
  retry amplification during backend failures. Query endpoints may be
  semantically read-only even when called with POST; the Thanos Receive and
  Loki OTLP write routes have side effects. Do not retry writes unless
  backend idempotency or deduplication is established.
- **Local and global rate limits.** A local token bucket can smooth bursts
  and protect one Envoy process. Its effective fleet-wide allowance grows
  with replica count. Tenant-wide quotas or a stable fleet-wide limit require
  a shared rate-limit service, which adds a dependency and latency to the
  request path.
- **Adaptive concurrency.** Envoy can adjust in-flight request limits based
  on observed latency. This may help keep a saturated backend responsive,
  but it adds a control loop that needs an explicit latency target, load
  testing, and staged rollout. Keep static circuit breakers as a safety
  limit.
- **Authentication and other HTTP filters.** The current chain contains only
  the router. If `ext_authz`, `ext_proc`, or other per-request filters are
  added, include their service latency, timeout, failure behavior, and any
  request-body buffering in the throughput budget. Avoid adding filters
  without measuring their effect on the hot path.

### Preserve operational visibility and safe shutdown

- Keep the admin endpoint restricted to loopback as it is today. Admin
  endpoints can change Envoy behavior, so do not expose the interface through
  the Service.
- Error-only access logs limit volume while retaining failure detail. If
  successful request visibility is needed, prefer selective or sampled logs
  and avoid logging credentials or sensitive headers.
- Align Envoy draining and Kubernetes termination grace with the longest
  requests the gateway is expected to serve. The current grace period is 30
  seconds while stream and route durations are also capped at 30 seconds;
  rollout behavior should be tested with in-flight requests.
- Replica scaling and disruption policy are Kubernetes responsibilities.
  Circuit breaker thresholds are per Envoy process, so evaluate their
  aggregate effect when replicas scale.

## Suggested measurement sequence

1. Record request rate, active concurrency, payload sizes, and p50/p95/p99
   latency separately for query and write routes.
2. Record Envoy worker count, CPU throttling, memory, active downstream
   connections, upstream pool activity, timeouts, retries, and circuit
   breaker overflow.
3. Load test representative query and write traffic, then repeat with slow
   or unavailable backends and during pod termination.
4. Change one control at a time and compare throughput, tail latency,
   rejected work, and resource use before choosing defaults.

Useful Envoy stats include `server.concurrency`, `server.memory_allocated`,
`cluster.<name>.upstream_rq_pending_overflow`,
`cluster.<name>.upstream_cx_overflow`,
`cluster.<name>.upstream_rq_timeout`, and the HTTP connection manager's
downstream request-time histogram. Confirm exact names and labels against
the deployed Envoy build.

## Version and reference notes

The example uses Envoy `v1.39.1`, while the Go Envoy API dependency in
`go.mod` is `v1.37.0`. The Go bindings determine which typed fields the
generator can emit. Check field availability against both versions before
adding a setting; fields introduced after the binding version may require a
dependency update. Validate generated bootstrap with the exact Envoy image
when implementation begins.

During the research pass, DNS resolution for `www.envoyproxy.io` failed, so
the official docs could not be opened live. The links below target Envoy
`v1.39.1` and should be checked before adopting version-specific behavior or
defaults.

- [Circuit breaking](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/upstream/circuit_breaking)
- [Overload manager](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/operations/overload_manager/overload_manager)
- [Load balancing](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/upstream/load_balancing/overview)
- [Health checking](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/upstream/health_checking)
- [Outlier detection](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/upstream/outlier)
- [HTTP/2](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/http/http2)
- [HTTP timeouts](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/http/http_conn_man/timeouts)
- [Local rate limiting](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/http/http_filters/local_rate_limit_filter)
- [Global rate limiting](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/http/http_filters/rate_limit_filter)
- [Adaptive concurrency](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/http/http_filters/adaptive_concurrency_filter)
- [TLS](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/security/ssl)
- [Statistics](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/observability/statistics)
- [Access logging](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/observability/access_log)
