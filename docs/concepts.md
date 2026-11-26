# Gateway concepts

An API groups routes to one upstream backend so you can control access to an
operation, such as reading or writing a resource.

When a server exposes an API, its API binding defines access rules for all of
that API's routes on the server. Use separate APIs for operations that need
different rules, even when they share a backend. For example, a client can be
allowed to query metrics without being allowed to write them.

## How the configuration fits together

| Concept     | Purpose                                                                  |
|-------------|--------------------------------------------------------------------------|
| Server      | Exposes selected APIs on one exact hostname, with optional TLS.          |
| API         | Groups routes for one upstream backend.                                  |
| Route       | Matches HTTP methods and an exact path, prefix, or regular expression.   |
| API binding | References an API under a server and defines public or protected access. |
| Upstream    | Sets the backend address, port, protocol, and optional TLS for an API.   |

Define APIs under top-level `apis` and expose them by name under
`servers[].apis`. A server can expose several APIs, and the same API can be
bound to several servers with different access rules. Clients use the hostname,
method, and path; API names are configuration identifiers.

Each binding requires protected `access` entries or explicit `public: true`.
See [authentication and authorization](auth/README.md) for configuring access.

## Separate read and write access

For a metrics backend, define one API for queries and another for ingestion:

```yaml
apis:
  - name: metrics-read
    upstream: {address: metrics-backend, port: 8080}
    routes:
      - methods: [GET]
        path: {exact: /api/v1/query}
      - methods: [GET]
        path: {exact: /api/v1/query_range}
  - name: metrics-write
    upstream: {address: metrics-backend, port: 8080}
    routes:
      - methods: [POST]
        path: {exact: /api/v1/write}
```

Bind both names under a server's `apis` list and configure their `access` entries
independently. See the [full configuration example](../config.example.yaml) for
complete bindings.

## Request flow

1. The request hostname selects a server.
2. Its API bindings and routes are checked in declaration order against the
   request method and path.
3. The matching binding's access rules determine whether the request is allowed.
4. An allowed request is forwarded to the API's upstream, with any configured
   path rewrite and request header processing.

An unknown hostname or path returns `404`. A matching path with an unsupported
method returns `405`. Requests denied by access rules do not reach the backend.
When paths overlap, declaration order matters; place more specific routes
before broader matches.

See the [configuration reference](configuration-reference.md#apis-upstreams-and-routes)
for route fields and the [Envoy behavior guide](envoy.md#listener-and-routes)
for TLS and generated routing details.
