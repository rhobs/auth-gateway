# API keys

## Authentication

Clients send a key in the configured credential header (default `X-API-Key`).
Define one named API-key authenticator per gateway configuration. All servers
selecting it share the same credential set:

```yaml
authenticators:
  - name: partner-key
    api_key:
      secret: auth-gateway-api-keys
      header: X-Partner-Key
    attributes:
      tenant_id: {credential: true}
      writer_id: {credential: true}
      requested_tenant: {header: X-Tenant}
```

`credential: true` reads a value bound to the issued key in the Secret.
`header: X-Tenant` reads the original request header; it is separate from
the `X-Partner-Key` credential header. For example, one Secret binding could
contain these values:

| Issued key | `tenant_id` | `writer_id` |
| --- | --- | --- |
| `example-partner-key` | `client-123` | `writer-17` |

Create the `auth-gateway-api-keys` Secret in the gateway Deployment's
`kubernetes.namespace` before deploying. The [Secret file format](../envoy.md#api-key-secret-format)
is documented with the deployment details. The `secret` field can be omitted
for file-based Envoy deployments. Keep issued keys and Secret manifests out
of version control.

A client sends both the key and the tenant it requests:

```http
POST /metrics/api/v1/receive HTTP/1.1
Host: partner.auth.example.com
X-Partner-Key: example-partner-key
X-Tenant: client-123
Content-Length: 0
```

The key must be valid even when a grant checks only a header-backed attribute.
A missing or empty `X-Tenant` leaves `requested_tenant` unset. Updating the
Secret replaces the accepted key set without restarting the gateway. Use an
explicit empty credential set in the Secret to revoke every key.

## Authorization and forwarding

This grant requires the original values bound to the key and the original
`X-Tenant` value. Select the authenticator and policy on the same server:

```yaml
authorization_policies:
  - name: partner-metrics-writers
    grants:
      - authenticator: partner-key
        apis: [metrics-write]
        attributes:
          tenant_id: [client-123]
          writer_id: [writer-17]
          requested_tenant: [client-123]

servers:
  - hostname: partner.auth.example.com
    authentication:
      any_of: [partner-key]
    authorization:
      any_of: [partner-metrics-writers]
    apis: [metrics-write]
```

All listed attributes must match. The header is caller-supplied, so include
a credential-bound condition when access must also be tied to the issued
key. A missing or unlisted value is denied before the backend receives the
request.

The full [gateway example](../../config.auth.example.yaml) maps
`tenant_id: client-123` to `team-a` for upstream use. A route can also map
`requested_tenant` to an output header, and `metrics.labels` can use its
processed value:

```yaml
processing:
  - name: upstream-tenants
    type: attribute-mapper
    attributes:
      requested_tenant:
        mappings:
          client-123: team-a

apis:
  - name: metrics-write
    metrics:
      labels:
        requested_tenant: requested_tenant
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - methods: [POST]
        path: {exact: /metrics/api/v1/receive}
        processing:
          request_headers:
            - name: X-Requested-Tenant
              from_attribute: requested_tenant
```

For the request above, the grant checks `client-123`, while the route sends
`X-Requested-Tenant: team-a` and the metric label uses `team-a`. The original
`X-Tenant: client-123` also reaches the backend unless it is configured as a
managed output header. Changing a mapping updates only the processing
ConfigMap. Changing the credential header, attribute sources, or grants
requires regenerating the static configuration and rolling out the Deployment.
