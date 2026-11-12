# External authorization

Use `ext_authz` when a gRPC policy service decides whether a request can reach
an API. It can run after local JWT, API-key, or server mTLS authentication. An
access entry can also omit local authentication so the service authenticates
and authorizes the request itself.

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
    attributes:
      - name: requested_tenant
        from_source: header
        value: X-Tenant
      - name: tenant_id
        from_source: authenticator
        value: tenant_id
```

`request_headers` is the explicit allowlist of request headers sent in the
Check request. Include credentials the policy needs. List those same headers
in `credential_headers` so they are removed before the API upstream. The
gateway rejects repeated selected credentials before the check.
The native API-key filter hides a locally verified key before the Check call;
the policy service receives its declared attributes instead.

Each `attributes` entry names a value sent in the Check request's
`auth_gateway.ext_authz.attributes` metadata namespace. A `header` source
reads the named safe request header; it must be in `request_headers` and cannot
be a credential header. An `authenticator` source uses an attribute declared
by every selected local authenticator on an access entry. The name and value
must match. Only nonempty scalar strings are sent. A selected access entry
without local authentication sends no authenticator attributes.

Every fixed attribute declared under `apis[].attributes` on the matched API is
sent automatically in the same namespace when an access entry uses this service.
Do not repeat fixed attributes under `ext_authz_services[].attributes`. For
example, an API attribute `{name: role, from_source: fixed, value: "metrics:read"}`
is available to the policy service as:

```go
fields := request.GetAttributes().GetMetadataContext().
    GetFilterMetadata()["auth_gateway.ext_authz.attributes"].GetFields()
role := fields["role"].GetStringValue() // "metrics:read"
```

The policy should check that a required key is present. A route without an
`ext_authz` access entry sends no Check request.

## Select it on an access entry

Set `authorization.ext_authz` instead of `authorization.grants`. The entries
below share one policy service while using different authentication methods.

```yaml
servers:
  - hostname: query.example.com
    apis:
      - name: metrics-query
        access:
          - name: internal
            match:
              headers:
                - name: X-Tenant
                  expression: equals
                  value: internal
            authentication:
              jwt: {providers: [internal-jwt]}
            authorization:
              ext_authz: {service: policy}
          - name: partner-key
            match:
              headers:
                - name: X-Tenant
                  expression: equals
                  value: partner
                - name: X-Partner-Key
                  expression: present
            authentication:
              api_key: {authenticator: partner-key}
            authorization:
              ext_authz: {service: policy}
          - name: external
            match:
              headers:
                - name: X-Tenant
                  expression: equals
                  value: external
            authorization:
              ext_authz: {service: policy}
```

For JWT-first access, the Check request also includes the complete parsed,
verified JWT payload under `envoy.filters.http.jwt_authn`, keyed by provider
name. This includes claims beyond those declared as gateway attributes and
preserves nested objects and lists. The policy service can use the route's API
and access labels to distinguish entries. For API-key and mTLS access, use
declared authenticator attributes; a dedicated mTLS server verifies its client
certificate before the Check call. Header-sourced values are still request
input, so the policy service must decide whether to trust or authorize them.

The gateway can use declared header attributes in managed upstream headers and
metric labels. Values are passed unchanged from their sources. Declare a
separate source attribute when an upstream needs a different value.

## Request outcome

An explicit Check denial returns the HTTP status selected by the policy
service. A Check error, connection failure, or timeout returns `503`. The
gateway rejects Check responses that try to change request headers. The
selected credential headers are removed before an allowed request reaches the
API upstream. Changes to the service or access entries require regenerating
the resources and explicitly rolling out the Envoy Deployment.
