# Client-certificate mTLS

mTLS is a dedicated HTTPS server mode for certificate-authenticated write APIs.
It always requires a trusted client certificate during TLS establishment.
JWT and API-key authentication cannot be enabled on any API bound to that
server. Other servers may expose the same API with different methods.

## Configuration

Define an explicit client CA and select the authenticator in the server's TLS
settings. Each access entry inherits that identity and grants its own access:

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
    tls_config:
      secret: gateway-tls
      mtls: {authenticator: partner-cert}
    apis:
      - name: metrics-write
        access:
          - tenant: client-123
            match:
              headers:
                X-Tenant: {exact: client-123}
            authorization:
              grants:
                - authenticator: partner-cert
                  attributes:
                    tenant_id: ['spiffe://partners.example.com/client-123']
                    writer_id: [writer-17.partners.example.com]
```

Create the serving TLS Secret and client CA ConfigMap in the gateway namespace
before deployment. File-based output can instead use absolute certificate,
private key, and CA `filename` paths. Client trust has no system CA fallback.
Define `metrics-write` and its forwarding as in the
[full configuration](../../config.example.yaml).

Any `access[].authentication` on this server, grants naming another
authenticator, public bindings, or a non-mTLS validator reference are
configuration errors. There is no optional-certificate mode. Bearer or key
headers do not replace the required client certificate.

## Certificate attributes and authorization

`uri_san` and `dns_san` read the verified certificate's subject alternative
names. Common names and other certificate fields are not attributes. At most
one URI SAN and one DNS SAN are accepted; multiple values and commas in SAN
values are denied before the backend.

All grant conditions must match. A trusted certificate without an applicable
grant receives `403`. Missing or untrusted certificates fail the TLS handshake
before an HTTP request is processed. A grant may omit `attributes` or use `{}`
to explicitly trust any certificate accepted by the configured CA. This still
requires certificate authentication.

A `header` source captures the original request value. It can supply the
right-hand side of `equals_attribute` when that header also participates in
`match.headers`. A header alone cannot supply a credential condition. Forwarded
headers and metric labels preserve their declared source values.

## CA updates

Kubernetes mounts the client CA ConfigMap as a projected directory. Envoy
reloads a valid changed bundle for new TLS connections without replacing the
Pod. Existing connections keep their original validation result. File-based
deployments must update the configured CA file atomically in its watched
parent directory. Access or validator configuration changes require
regeneration and an explicit Deployment rollout.
