# Local playground

This playground runs Envoy, an OpenTelemetry Collector, Jaeger, [navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server), and Prometheus in Docker Compose. It routes the `metrics-write` and `logs` APIs from [config.example.yaml](../config.example.yaml) to `https://httpbin.org/anything`; the query API is omitted. The two JWT issuers use [Mock OAuth JSON token callbacks](https://github.com/navikt/mock-oauth2-server#token-customization-via-json_config).

Requirements: Docker Compose v2, Go, OpenSSL, `jq`, and `curl`. Go is used by `make generate` to refresh the Envoy bootstrap from the library. No local Go server is kept running.

From the repository root, enter `playground` and start the stack. Run the remaining commands from that directory. Startup generates Envoy and collector configs plus both demo JWTs:

```sh
cd playground
make start
```

The Envoy bootstrap comes from [config.yaml](config.yaml), without Kubernetes resources. The collector config is generated from `observability.metrics` and `observability.tracing` in the same file. Envoy sends OTLP/gRPC spans to the collector, which forwards them to Jaeger. After editing the config, run `make generate` and restart the stack with `make start`. Generation refreshes the checked-in [envoy.yaml.golden](envoy.yaml.golden) and [otel-collector.yaml.golden](otel-collector.yaml.golden), then copies them to `generated/` for Compose.

[credentials.yaml](credentials.yaml) is a complete Envoy API-key ECDS resource with demo keys. Compose mounts this file directly where Envoy reads its API keys. Edit it to test different local demo keys and attribute values, then run `make start` to restart Envoy.

The four local servers share port 8080. `unprotected.localhost` exposes the browser-friendly public route. The `api-key.localhost`, `jwt.localhost`, and `mixed.localhost` servers expose the protected write routes:

- `GET /anything` on `unprotected.localhost` forwards to `https://httpbin.org/anything`.
- `POST /metrics/api/v1/receive` rewrites to `/anything`.
- `POST /logs/otlp/v1/logs` rewrites to `/anything/v1/logs`.

The `metrics-write` and `logs` APIs have separate authorization grants. The metrics JWT and `metrics-demo-key` work only for `metrics-write`; the logs JWT and `logs-demo-key` work only for `logs`. `jwt.localhost` accepts either issuer, `api-key.localhost` accepts API keys, and `mixed.localhost` accepts either a JWT or an API key. A credential for the other API is denied with 403. `unprotected.localhost` needs no credential.

Both protected write routes set `X-Authenticated-User` from the verified `user_id` attribute. httpbin echoes `metrics-writer` for metrics credentials and `logs-writer` for logs credentials. The gateway replaces any caller-supplied value for this header and strips the original API key or bearer token before forwarding.

Mock OAuth issues separate JWTs from its `metrics` and `logs` issuers. Their issuer claims are `https://auth.localhost:8443/metrics` and `https://auth.localhost:8443/logs`; each has its own JWKS endpoint. `make start` requests both tokens automatically. Run `make token` to refresh them. The raw JWTs are stored with owner-only permissions in `generated/metrics.jwt` and `generated/logs.jwt`.

To inspect an OAuth response as JSON or print just the raw access token, request either issuer by changing `metrics` to `logs` in the URL:

```sh
token_response=$(curl --silent --show-error --fail \
  --resolve auth.localhost:8443:127.0.0.1 \
  --cacert generated/mock-oauth2.crt \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=playground-client' \
  --data-urlencode 'client_secret=playground-secret' \
  https://auth.localhost:8443/metrics/token)
printf '%s\n' "$token_response" | jq .
printf '%s\n' "$token_response" | jq -r '.access_token'
```

The commands below send API requests through Envoy. Envoy validates the credentials, sets `X-Authenticated-User` from the verified `user_id` attribute, and removes the API-key and bearer-token headers before forwarding to httpbin:

```sh
curl --request POST \
  --header "Authorization: Bearer $(cat generated/metrics.jwt)" \
  --data 'sample=metrics' \
  http://jwt.localhost:8080/metrics/api/v1/receive

curl --request POST \
  --header "Authorization: Bearer $(cat generated/logs.jwt)" \
  --header 'Content-Type: application/json' \
  --data '{"resourceLogs":[]}' \
  http://jwt.localhost:8080/logs/otlp/v1/logs

curl --request POST \
  --header 'X-API-Key: metrics-demo-key' \
  --data 'sample=metrics' \
  http://api-key.localhost:8080/metrics/api/v1/receive

curl --request POST \
  --header 'X-API-Key: logs-demo-key' \
  --header 'Content-Type: application/json' \
  --data '{"resourceLogs":[]}' \
  http://mixed.localhost:8080/logs/otlp/v1/logs
```

To see the different issuers and keys rejected by route authorization, use the metrics token or key on `/logs/otlp/v1/logs`, or the logs token or key on `/metrics/api/v1/receive`. Those requests should return 403.

Prometheus is available at `http://127.0.0.1:9090`; the collector endpoint is `http://127.0.0.1:8889/metrics`. The collector scrapes Envoy's built-in stats and custom request counter every five seconds, then removes Envoy's `envoy_http_lua_` prefix from Lua metric names. This config sets `observability.metrics.custom_metric_name` to `gateway_http_requests_total`, so Prometheus sees `gateway_http_requests_total` with `api`, `http_status_code`, and `user_id` labels. `auth_gateway_http_requests_total` is the default counter name when `observability.metrics.custom_metric_name` is omitted, so it has no series in this playground. Try `gateway_http_requests_total{api="metrics-write"}` and `gateway_http_requests_total{api="logs",user_id="logs-writer"}` in the Prometheus expression browser. Envoy's admin port remains loopback-only; the collector shares Envoy's network namespace to scrape it. The metrics database is temporary and is removed when the stack is stopped. Set `PROMETHEUS_HOST_PORT` to change the local Prometheus port and `OTEL_METRICS_HOST_PORT` to change the collector port.

Jaeger is available at `http://127.0.0.1:16686`. Send a request through Envoy using one of the commands above, then select `auth-gateway-playground` in Jaeger's service list to view its trace. Each sampled request includes the gateway span and an upstream span. The trace store is in memory and is removed when the playground stops. Set `JAEGER_HOST_PORT` to change the local Jaeger UI port.

The token issuer URLs use `auth.localhost` because that is the host used when requesting tokens. Envoy fetches the separate JWKS documents from `mock-oauth2-server` over the Compose network. The generated certificate covers both hostnames and is trusted by Envoy. `make generate` replaces an older certificate that lacks the service-name SAN. Set `HOST_PORT` to change the local Envoy port; if you change `listener.port` in the config, set `ENVOY_PORT` to the same value. `OAUTH_HOST_PORT` changes the OAuth port on your host. Tokens include that port in `iss`, so update both JWT `issuer` values in `config.yaml` if you change it. JWKS requests use the OAuth container's internal port 8443 and Compose service name. If you change the internal port, update `SERVER_PORT`, the Compose port mapping, and both JWKS URLs as well.

`make run` starts the stack and follows its logs. Press Ctrl-C to stop following logs, then run `make stop` to stop the containers. `make clean` stops the stack and removes generated files; it keeps `credentials.yaml` and both checked-in YAML goldens.
