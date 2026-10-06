# API keys

## Authentication

Clients send a key in the configured request header (default `X-API-Key`).
In Kubernetes, the gateway reads keys from a Secret. Define one named API-key
authenticator per gateway configuration; all servers selecting it share the
same credential set:

```yaml
authenticators:
  - name: partner-key
    api_key:
      secret: auth-gateway-api-keys
      header: X-Partner-Key
      attributes: [tenant_id, writer_id]
```

`api_key.attributes` declares the names a key may provide. The Secret below
binds `tenant_id` and `writer_id` values to one key. Grants check the original
values; route headers and metric labels can use processed values. A missing
value cannot satisfy a grant that requires it.

The `header` field is optional. The `secret` field is required for Kubernetes
deployments and can be omitted for file-based Envoy. Create the Secret in the
configured `kubernetes.namespace` before deploying the gateway. The
[full example](../../config.auth.example.yaml) uses `observability`:

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

The `key` is what clients send. The plain-text `client` value gives that key
its original attribute values. The gateway already knows the authenticator
from its configuration. List every declared attribute in alphabetical order;
use an empty value when an attribute is absent. Attribute values cannot
contain semicolons. Use a different key value for real clients.

A client sends its issued key in the configured header:

```http
POST /metrics/api/v1/receive HTTP/1.1
Host: partner.auth.example.com
X-Partner-Key: example-partner-key
Content-Length: 0
```

Updating the Secret replaces the accepted key set without restarting the
gateway. Set `credentials: []` under `ApiKeyAuth` in the Secret to revoke every
key. Keep real key values and deployed Secret manifests private and out of
version control.

## Authorization

A grant checks the original attributes stored with a verified key. This
policy allows `metrics-write` only when both listed attributes match.
Select the authenticator and policy on the same server:

```yaml
authorization_policies:
  - name: partner-metrics-writers
    grants:
      - authenticator: partner-key
        apis: [metrics-write]
        attributes:
          tenant_id: [client-123]
          writer_id: [writer-17]

servers:
  - hostname: partner.auth.example.com
    authentication:
      any_of: [partner-key]
    authorization:
      any_of: [partner-metrics-writers]
    apis: [metrics-write]
```

Define `metrics-write` under `apis` as in the full example. The grant checks
the raw `client-123` and `writer-17` values in `client`; missing or unlisted
values are denied. The full example then maps `tenant_id` for upstream
requests:

```yaml
processing:
  - name: upstream-tenants
    type: attribute-mapper
    attributes:
      tenant_id:
        mappings:
          client-123: team-a
```

The `metrics-write` route binds those attributes to upstream headers:

```yaml
processing:
  request_headers:
    - name: X-Scope-OrgID
      from_attribute: tenant_id
    - name: X-Writer-ID
      from_attribute: writer_id
```

The key's `tenant_id=client-123` becomes `X-Scope-OrgID: team-a`;
`writer_id=writer-17` becomes `X-Writer-ID: writer-17`. Authorization still
checks the raw values.

Changing this mapping updates only the processing ConfigMap. Changing the key
header, declared attributes, or grants requires regenerating the configuration
and rolling out the Deployment. Changing only credential values requires a
Secret update.
