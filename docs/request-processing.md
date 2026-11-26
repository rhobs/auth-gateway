# Request processing

Attach an external gRPC processor to a route with `processing.ext_proc`. Use it
for request inspection, body transformation, or an application-specific rejection.
The gateway resolves authentication and authorization first. Deploy and configure
the processor separately; the gateway does not define application policy.

Declare a service and select it from the API route:

```yaml
ext_proc_services:
  - name: transform
    upstream:
      address: processor.observability.svc.cluster.local
      port: 9000
      http_protocol: http2
    message_timeout: 200ms
    failure_mode_allow: false
    request_attributes: [request.method, request.path]
    mutable_request_headers: [x-processed, content-length]

apis:
  - name: ingest
    attributes:
      - name: operation
        from: {fixed: ingest}
    upstream: {address: receiver, port: 8080}
    routes:
      - methods: [POST]
        path: {expression: equals, value: /ingest}
        processing:
          ext_proc:
            service: transform
            request_body_mode: buffered
            request_body_buffer_limit_bytes: 2097152
```

This fragment uses plaintext HTTP/2. For verified TLS, add `upstream.tls_config`
with the processor's certificate name and optional `trusted_ca`. CA ConfigMaps
must exist in the gateway namespace. Complete the server and access configuration
as shown in [the full example](../config.example.yaml). Public bindings can also
attach a processor.

A client sends an ordinary request:

```sh
curl -X POST https://gateway.example.test/ingest \
  -H 'Content-Type: text/plain' --data 'request payload'
```

The processor receives the authorized request after credential removal and
managed header mappings. It can inspect all remaining headers. Resolved scalar API and
selected access attributes appear under
`metadata_context.filter_metadata["auth_gateway.ext_proc.attributes"]`, with
their original names and values. For this example, `operation` is `ingest`.
Verified JWT payloads appear separately under `envoy.filters.http.jwt_authn`.
Configured native Envoy properties appear in
`ProcessingRequest.attributes["envoy.filters.http.ext_proc"]`. The default
`request_attributes` list is empty; native properties are selected per service.
Missing or empty working attribute values are omitted. No tenant attribute is
required.

Each route selects one named processor. Routes without an attachment and
generated denial, `404`, and `405` routes do not call a processor. Reusing a
service lets routes select different request stages:

| Setting | Default | Behavior |
| ------- | ------- | -------- |
| `request_header_mode` | `send` | `send` delivers request headers; `skip` omits them. |
| `request_body_mode` | `none` | `none` omits the body; `buffered` sends the complete body; `buffered_partial` processes a buffered prefix when the buffer fills; `streamed` processes chunks; `full_duplex_streamed` allows independently sized response chunks. |
| `request_trailer_mode` | `skip` | `send` delivers trailers when present; required for full duplex bodies. |

Omitting `request_body_buffer_limit_bytes` inherits the listener buffer limit.
An override must equal or exceed `listener.per_connection_buffer_limit_bytes`;
Envoy only raises the buffer limit when applying a route override.

A buffered request exceeding the effective buffer limit receives `413` before
reaching the upstream. Partial mode can leave the remainder unchanged; a
processor must account for this. Streaming modes use flow control and do not
promise that a late rejection can prevent earlier chunks reaching the upstream.
Full duplex processors must use `StreamedBodyResponse` and preserve protocol
ordering. Envoy does not apply `message_timeout` in full duplex mode; listener
and route timeouts still bound the client request.

Header changes require entries in `mutable_request_headers`; the default list
is empty. Native mutation rules reject forbidden changes. Credentials, gateway
controls, Envoy headers, connection headers, and managed output headers cannot
be granted mutation permission. Explicitly allowing `:path` trusts the processor
to change the forwarded path or query. The authorized route and upstream stay
selected even when the processor requests route-cache clearing. Normal route
rewrites still apply after processing.

When a buffered processor changes body length, it must remove or correctly
update `content-length`; include that header in its mutation permissions. Envoy
removes content length automatically in streamed, partial, full duplex, and
buffered-with-skipped-headers modes. The gateway retains this native framing
behavior.

Explicit processor rejections preserve the processor's HTTP status and body.
By default, native processing failures fail closed. `failure_mode_allow: true`
applies Envoy's fail-open semantics to processing failures; it does not turn
explicit rejections into success or roll back mutations already applied.

Response processing, observation mode, processor-driven mode overrides, and
received metadata writes are disabled. Processor configuration and route
attachments live in the static bootstrap. Regenerate and apply the configuration,
then explicitly roll out the Deployment.

See the [configuration reference](configuration-reference.md#external-processing-services),
[Envoy ext_proc configuration](https://www.envoyproxy.io/docs/envoy/v1.39.1/api-v3/extensions/filters/http/ext_proc/v3/ext_proc.proto),
and [processing protocol](https://www.envoyproxy.io/docs/envoy/v1.39.1/api-v3/service/ext_proc/v3/external_processor.proto).
The generic test binary lives in
[`e2e/cmd/ext-proc-test-server`](../e2e/cmd/ext-proc-test-server/main.go); it reflects
inputs into an upstream header and uppercases request bodies for e2e assertions.
