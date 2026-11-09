# External authorization

Use `ext_authz` when a gRPC policy service must decide whether a request can
reach an API. The service can authorize an identity already verified by JWT,
API key, or server mTLS. An access entry can also omit local authentication so
the service authenticates and authorizes the request.

## Configure the service

Define a named service with an HTTP/2 TLS upstream. Envoy verifies its server
certificate. In Kubernetes, create the CA ConfigMap in the gateway namespace
before applying the generated gateway resources.

```yaml
ext_authz_services:
  - name: policy
    upstream:
      address: policy.observability.svc.cluster.local
      port: 9000
      http_protocol: http2
      tls_config:
        server_name: policy.observability.svc.cluster.local
        trusted_ca:
          config_map: {name: policy-ca, key: ca.pem}
    timeout: 300ms
    request_headers: [authorization, x-tenant]
    credential_headers: [authorization]
```

`request_headers` is an explicit allowlist of request headers sent in the
Check request. Include the credentials the policy needs. List those same
headers in `credential_headers` so they are removed before the API upstream.
The gateway rejects repeated selected credentials before the check. Use a
timeout that fits the policy service's expected latency.

## Select it on an access entry

Set `authorization.ext_authz` instead of `authorization.grants`. The first
entry below runs local JWT verification before calling the policy service. The
second sends the selected `authorization` header to the policy service, which
must authenticate and authorize it. The entries can share one service.

```yaml
servers:
  - hostname: query.example.com
    apis:
      - name: metrics-query
        access:
          - name: internal
            match:
              headers:
                X-Tenant: {exact: internal}
            authentication:
              jwt: {providers: [internal-jwt]}
            authorization:
              ext_authz:
                service: policy
                response_attributes:
                  authorized_tenant: [identity, tenant]
          - name: partner
            match:
              headers:
                X-Tenant: {exact: partner}
            authorization:
              ext_authz:
                service: policy
                response_attributes:
                  authorized_tenant: [identity, tenant]
```

The policy service receives the API name and selected access label as route
metadata. For JWT-first access it also receives verified JWT metadata. A
dedicated mTLS server has already verified the client certificate before the
Check call. The service should use these verified values rather than trusting
caller-supplied identity headers.

The Check response's `dynamic_metadata` can supply declared
`response_attributes`. In the example, `identity.tenant` becomes
`authorized_tenant` when it is a nonempty string. You can use that attribute
in `apis[].routes[].processing.request_headers[].from_attribute`, API metric
labels, or fault selectors. A route that requires a missing or non-string
attribute returns `403` before reaching the upstream. The gateway does not
translate or normalize the value.

## Request outcome

An explicit Check denial returns the HTTP status selected by the policy
service. A Check error, connection failure, or timeout returns `503`. The
gateway rejects Check responses that try to change request headers; the policy
service must return identity data through `dynamic_metadata`. The selected
credential headers are removed before an allowed request reaches the API
upstream. Changes to the service or access entries require regenerating the
resources and explicitly rolling out the Envoy Deployment.
