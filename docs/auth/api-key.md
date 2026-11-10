# API keys

## Authentication

Clients send a key in the configured credential header (default `X-API-Key`).
Define one named API-key authenticator per gateway configuration. All access entries
selecting it share the same credential set:

```yaml
authenticators:
  - name: partner-key
    api_key:
      secret: auth-gateway-api-keys
      header: X-Partner-Key
    attributes:
      - name: tenant_id
        from_source: credential
        value: tenant_id
      - name: upstream_tenant
        from_source: credential
        value: upstream_tenant
      - name: writer_id
        from_source: credential
        value: writer_id
      - name: requested_tenant
        from_source: header
        value: X-Tenant
```

`from_source: credential` reads the named value bound to the issued key in the Secret.
`from_source: header` reads the original request header; it is separate from
the `X-Partner-Key` credential header. The entry's `name` is the gateway
attribute. Its `value` names the key in the credential, so the two names can
differ. For example, one Secret binding could contain these values:

| Issued key | `tenant_id` | `upstream_tenant` | `writer_id` |
| --- | --- | --- | --- |
| `example-partner-key` | `client-123` | `team-a` | `writer-17` |

Create the `auth-gateway-api-keys` Secret in the gateway Deployment's
`kubernetes.namespace` before deploying. See [API-key Secret format](#api-key-secret-format)
for the credential document and Secret layout. The `secret` field can be omitted
for file-based Envoy deployments. Keep issued keys and Secret manifests out of
version control.

### API-key Secret format

The library accepts one credential document. Load it with
`gateway.LoadAPIKeyCredentials` and pass the result with the selected
authenticator to `gateway.APIKeySecret` to build the Kubernetes Secret:

```yaml
credentials:
  - key: example-partner-key
    attributes:
      tenant_id: client-123
      upstream_tenant: team-a
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
          '@type': type.googleapis.com/envoy.extensions.filters.http.api_key_auth.v3.ApiKeyAuth
          credentials:
            - client: tenant_id=client-123;upstream_tenant=team-a;writer_id=writer-17
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
Keys cannot contain commas. Credential attribute values cannot contain
semicolons and must be at most 8191 bytes each, matching Envoy's metadata extraction limit. Other allowed characters,
including equals signs and percent-encoded text, keep their original values.
Missing bindings leave the corresponding attributes unset. Replace the
example key with a unique value for each client.

Kubernetes stores `api-keys.yaml` as opaque Secret data and does not validate
the Envoy resource inside it. Hand-editing that data or changing it through
GitOps can bypass the gateway's credential validation. Generate the Secret
from validated API-key credentials rather than editing the Envoy resource by
hand. Envoy's `--mode validate` checks the bootstrap but does not validate
this file-backed ECDS resource. See
[Envoy file updates](../envoy.md#files-and-reloads) for its runtime
failure counters and monitoring.

A client sends both the key and the tenant it requests:

```http
POST /metrics/api/v1/receive HTTP/1.1
Host: partner.auth.example.com
X-Partner-Key: example-partner-key
X-Tenant: client-123
Content-Length: 0
```

The selected key must be valid and its credential attributes must satisfy the
grant. A missing or unmatched `X-Tenant` is denied before the backend. Updating the
Secret replaces the accepted key set without restarting the gateway. Setting
`credentials: []` in a valid credential document revokes every key. Deleting or
corrupting the Secret is not a revocation method.

## Authorization and forwarding

This entry selects a requested tenant and requires the original values bound
to its key. Optional equality can bind a shared tenant list to the particular
verified credential tenant:

```yaml
servers:
  - hostname: partner.auth.example.com
    apis:
      - name: metrics-write
        access:
          - tenant: client-123
            match:
              headers:
                X-Tenant: {exact: client-123}
            authentication:
              api_key: {authenticator: partner-key}
            authorization:
              grants:
                - authenticator: partner-key
                  attributes:
                    tenant_id: {equals_attribute: requested_tenant}
                    writer_id: [writer-17]
```

All listed conditions must match. A client cannot request another tenant just
by changing a header. An invalid JWT does not affect a selected API-key entry,
and a valid JWT cannot replace a missing key. Known credential headers are
removed before forwarding.

When the upstream needs a different tenant value, supply an additional
credential attribute. The credential document above includes
`upstream_tenant: team-a` alongside `tenant_id: client-123`. Keep the grant on
`tenant_id` and select `upstream_tenant` for the upstream header and metric
label:

```yaml
apis:
  - name: metrics-write
    metrics:
      labels:
        tenant: upstream_tenant
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - methods: [POST]
        path: {exact: /metrics/api/v1/receive}
        processing:
          request_headers:
            - name: X-Scope-OrgID
              from_attribute: upstream_tenant
```

The grant checks `client-123`, while the route sends `X-Scope-OrgID: team-a`
and the metric label uses `team-a`, directly from the key's credential
attribute. The original `X-Tenant: client-123` also reaches the backend unless
it is configured as a managed output header. Updating credential values uses
the same Secret rotation described above. Changing the credential header,
attribute sources, header or metric bindings, or grants requires regenerating
the static configuration and rolling out the Deployment.
