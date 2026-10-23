# Client-certificate mTLS

## Authentication

An mTLS authenticator validates client certificates against an explicit CA
bundle. Select it only on an HTTPS server:

```yaml
authenticators:
  - name: partner-cert
    mtls:
      trusted_ca:
        config_map: {name: partner-client-ca, key: ca.crt}
    attributes:
      tenant_id: {uri_san: true}
      writer_id: {dns_san: true}
      requested_tenant: {header: X-Tenant}

servers:
  - hostname: cert.auth.example.com
    tls_config: {secret: gateway-tls}
    authentication:
      any_of: [partner-cert]
    apis: [metrics-write]
```

`trusted_ca` is required and has no system CA fallback. In Kubernetes, create
the referenced ConfigMap in the gateway namespace before deploying. File-based
Envoy output can instead use an absolute `filename` for a PEM CA bundle that
already exists in the Envoy container. A server can select at most one mTLS
authenticator.

A certificate-only server and any `all_of` server request a client certificate
during the TLS handshake. A mixed `any_of` server permits a connection without
a certificate, so another selected method can authenticate it. If a client
sends an untrusted certificate, Envoy rejects the TLS handshake. For mixed
`any_of`, authentication priority is JWT, mTLS, then API key. A valid
higher-priority identity without an authorization grant is denied rather than
falling back to a lower-priority credential.

## Certificate attributes and authorization

`uri_san: true` and `dns_san: true` read the verified certificate's URI and DNS
subject alternative names. Common names and other certificate fields are not
attributes. A certificate may contain at most one URI SAN and one DNS SAN;
multiple values and SAN values containing commas are rejected because Envoy
formats these values as comma-separated text. A `header` source reads the
original request header and still requires a trusted client certificate for
the mTLS grant to apply.

Grant attributes match original SAN or header values. A grant can omit
`attributes` (or set it to `{}`) to allow any certificate trusted by the
configured CA for its listed APIs:

```yaml
authorization_policies:
  - name: partner-writers
    grants:
      - authenticator: partner-cert
        apis: [metrics-write]
        attributes:
          tenant_id: [spiffe://partners.example.com/client-123]
          writer_id: [writer-17.partners.example.com]

servers:
  - hostname: cert.auth.example.com
    tls_config: {secret: gateway-tls}
    authentication:
      any_of: [partner-cert]
    authorization:
      any_of: [partner-writers]
    apis: [metrics-write]
```

All attributes in a grant must match. Forwarded headers and metric labels use
the declared source values. The [configuration
reference](../configuration-reference.md) lists the accepted fields and
constraints.

## CA updates

Kubernetes mounts client CA ConfigMaps as projected files. Envoy reloads a
valid changed CA bundle for new TLS connections without replacing the gateway
Pod. Existing connections keep the certificate validation result from their
handshake. With file-based output, place the CA bundle at its configured path
and let Envoy watch the parent directory.
