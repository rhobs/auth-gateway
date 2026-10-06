# API keys

## Authentication

Envoy reads a key from the configured request header (default `X-API-Key`)
and checks it against a mounted file, typically supplied by a Kubernetes
Secret. Define one named API-key authenticator per gateway configuration;
all servers selecting it share the same credential set:

```yaml
authenticators:
  - name: partner-key
    api_key:
      secret: auth-gateway-api-keys
      header: X-Partner-Key
      attributes: [tenant_id, writer_id]
```

`api_key.attributes` declares the names a key may provide. In this example,
each key can carry `tenant_id` and `writer_id`; their string values are set
per key in the credentials file below. Grants, route headers, and metric
labels can use these names. The Secret generator rejects undeclared names,
and a missing value cannot satisfy a grant that requires it.

The `header` field is optional. For Kubernetes deployments, the Secret
must be in the gateway Deployment's `kubernetes.namespace`. Put credentials
in a private file, for example:

```yaml
credentials:
  - key: "<random-opaque-key>"
    attributes:
      tenant_id: client-123
      writer_id: writer-17
```

From the repository root, generate and apply the Secret before deploying
the gateway. The [full example](../../config.auth.example.yaml) uses the
same authenticator name, header, and Secret:

```sh
go run ./examples/generate-api-key-secret \
  config.auth.example.yaml credentials.yaml api-key-secret.yaml
kubectl apply -f api-key-secret.yaml
```

Updating the Secret replaces the complete key set without restarting
the gateway. Use `credentials: []` to revoke every key. Keep the credentials
file and generated Secret manifest out of version control.

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
  - hostname: partner.example.com
    authentication:
      any_of: [partner-key]
    authorization:
      any_of: [partner-metrics-writers]
    apis: [metrics-write]
```

Define `metrics-write` under `apis` as in the full example. Missing or
unlisted attribute values are denied. Attribute mappings do not change
authorization. Changing the key header, declared attributes, or grants
requires regenerating the configuration and rolling out the Deployment.
Changing only credential values requires a Secret update.
