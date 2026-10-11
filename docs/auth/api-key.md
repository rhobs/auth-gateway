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
`kubernetes.namespace` before deploying. See [API-key Secret format](#api-key-secret-format)
for the credential document and Secret layout. The `secret` field can be omitted
for file-based Envoy deployments. Keep issued keys and Secret manifests out of
version control.

### API-key Secret format

The library accepts one credential document. Load it with
`config.LoadAPIKeyCredentials` and pass the result with the selected
authenticator to `config.APIKeySecret` to build the Kubernetes Secret:

```yaml
credentials:
  - key: example-partner-key
    attributes:
      tenant_id: client-123
      writer_id: writer-17
```

Only credential-backed attributes belong in this document. Header-backed
attributes come from each request. The generated Secret stores the Envoy
resource in `Secret.data["api-keys.yaml"]`. The equivalent manually written
Secret below uses `stringData` for readability. The `client` field lists
credential attributes alphabetically, with empty values for missing bindings:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-gateway-api-keys
  namespace: observability
type: Opaque
stringData:
  api-keys.yaml: |
    resources:
      - '@type': type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig
        name: envoy.filters.http.api_key_auth
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.common.matching.v3.ExtensionWithMatcher
          extension_config:
            name: envoy.filters.http.api_key_auth
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.api_key_auth.v3.ApiKeyAuth
              credentials:
                - client: tenant_id=client-123;writer_id=writer-17
                  key: example-partner-key
              forwarding:
                header: x-auth-gateway-api-key-client
                hide_credentials: true
              key_sources:
                - cookie: ""
                  header: x-partner-key
                  query: ""
```

The example `key_sources.header` matches `api_key.header: X-Partner-Key`.
Credential values cannot contain semicolons. Replace the example key with a
unique value for each client.

Kubernetes stores `api-keys.yaml` as opaque Secret data and does not validate
the Envoy resource inside it. Hand-editing that data or changing it through
GitOps can bypass the gateway's credential validation. Generate the Secret
from validated API-key credentials rather than editing the Envoy resource by
hand. Envoy's `--mode validate` checks the bootstrap but does not validate
this file-backed ECDS resource. See
[Envoy file updates](../envoy.md#kubernetes-files-and-reloads) for its runtime
failure counters and monitoring.

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
Secret replaces the accepted key set without restarting the gateway. Setting
`credentials: []` in a valid credential document revokes every key. Deleting or
corrupting the Secret is not a revocation method.

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
