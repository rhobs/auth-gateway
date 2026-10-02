# Server configuration implementation plan

## Summary

Implemented and verified. See `HANDOVER.md` for the current state, checks, and next step.

Replace the listener host lists and global TLS configuration with explicit server definitions. Each hostname serves exactly one protocol and exposes only its bound APIs.

Continue on `rhobs-1783-bootstrap`. The starting working tree contains the draft in `config.example.yaml`. Baseline `go test ./...` and `git diff --check` pass, but the draft example is unsupported by the original loader.

This step covers hostname, TLS, and API bindings. Authentication policies, JWT, mTLS, and tenant authorization remain separate work.

## Configuration contract

Keep the existing API definitions and listener port. Envoy always binds to the wildcard address for Kubernetes. Add a required server list:

```yaml
version: 1

listener:
  port: 8080

# Existing top-level API definitions remain here.

servers:
  - hostname: write.auth.example.com
    tls_config:
      secret: write-gateway-tls
    apis: [metrics-write, logs]

  - hostname: query.auth.example.com
    tls_config:
      secret: query-gateway-tls
    apis: [metrics-query]
```

- Add `Config.Servers []Server`. Each `Server` contains `Hostname string`, `TLSConfig *ServerTLS`, and `APIs []string`, using YAML keys `hostname`, `tls_config`, and `apis`. Reuse the existing certificate configuration type.
- Remove `listener.http_hosts`, `listener.https_hosts`, and top-level `server_tls`. Keep strict YAML decoding and reject these legacy fields. Keep `version: 1` for this bootstrap change.
- Require at least one server. Require exact DNS hostnames using the existing hostname rules. Reject duplicate hostnames across the entire list, including HTTP/HTTPS duplicates. Remove implicit wildcard HTTP.
- An absent TLS configuration selects HTTP. A non-nil TLS configuration selects HTTPS with server TLS. Preserve existing TLS protocol settings.
- Bind APIs by their existing names. Reject unknown names and repeated bindings within a server. Permit API reuse across servers and valid API definitions that remain unbound.
- Missing or empty server API bindings are valid and serve 404 for every path.
- Assemble routes in the order of `server.apis`, then in each API's route declaration order.
- Validate duplicate path/method combinations within each API and across APIs bound to the same server. Allow identical routes in separate APIs when they are bound to different servers.
- When a Secret is named, default paths to `/etc/<secret>/tls.crt` and `/etc/<secret>/tls.key`. Retain file-only TLS support without Kubernetes, including existing default paths when no Secret is named. Preserve explicit path overrides and existing path validation.
- Require a valid Secret name for each HTTPS server when generating Kubernetes resources. Defaults must continue to avoid mutating caller-owned configuration.

## Implementation changes

1. Update loading, defaults, validation, and generation to use server definitions. Resolve API references consistently while preserving binding order. Retain validation of all API definitions, including unbound ones, and report server configuration errors with their list index.
2. Keep one Envoy listener port. Generate one plaintext HTTP chain containing a virtual host per HTTP server. Generate a separate SNI-matched TLS chain and connection manager for every HTTPS server, even when certificates are shared. Each TLS manager accepts only its own HTTP authority. SNI for server A with authority for server B returns 404. Enable the TLS inspector when HTTPS is configured and provide no default TLS chain.
3. Generate routes, 405 responses, and `Allow` headers solely from each server's bound APIs. Preserve rewrites and the final 404 response. Keep upstream clusters shared by API name.
4. Generate one SDS resource per HTTPS server, using declaration indexes for `gateway_server_<index>` and `server-certificate-<index>.yaml`. Preserve SDS and certificate directory watches. Mount every generated configuration file in deterministic order.
5. Mount each distinct Secret/certificate-path/private-key-path binding read-only. Deduplicate identical bindings. Reject conflicting or overlapping certificate mount directories, including overlap with gateway or collector configuration directories. Use directory mounts so Secret projection and certificate rotation continue to work.
6. Expose HTTP and HTTPS Service ports only when corresponding servers exist. Both target the existing Envoy listener. Preserve metrics on port 8889 and existing Service port conflict checks.
7. Replace the draft example with complete server entries. Convert unit and e2e fixtures to explicit bindings. Update the README and TLS documentation with the format, breaking migration, certificate defaults, and shared Secret behavior. Test loading the root example and generating its Kubernetes output.

## Validation and handoff

Start with unit tests and goldens, then run live e2e coverage.

- Configuration: missing/empty servers, invalid/duplicate hostnames, legacy fields, unknown/repeated bindings, empty bindings, API reuse, unbound APIs, route conflicts scoped to servers, binding order, TLS defaults, and unchanged input after defaulting.
- Generation: HTTP virtual hosts and separate HTTPS chains contain only bound routes; 405 and `Allow` are scoped; empty servers return 404; clusters are shared; SDS files are unique; output is deterministic.
- Kubernetes: HTTP-only and mixed-protocol goldens, multiple HTTPS servers with distinct Secrets, HTTPS-only Service ports, mount deduplication/conflicts, and all generated ConfigMap files being mounted.
- Live e2e: two HTTP hosts with different API sets; two HTTPS hosts with different bindings and certificates; unknown hosts, unbound paths, wrong protocols, unknown SNI, and mismatched SNI/authority. Renew one certificate and check that it changes while the other certificate and gateway Pod UID stay unchanged.
- Keep namespace isolation and `Ordered` Ginkgo groups. Keep Kubernetes lifecycle operations in the framework and scenario helpers in the test package.

Regenerate goldens with `go test ./config -run Golden -update`, review changes, format modified Go files, and run:

```sh
make test
go vet ./...
go test -tags=e2e -run '^$' ./e2e
go vet -tags=e2e ./e2e
make -C e2e test
git diff --check
```

Run e2e with its default two Ginkgo processes. Record unavailable checks explicitly.

Review the relevant Jira scope before implementation. Commit tested steps on the feature branch and update `HANDOVER.md` with the schema, migration, and check results. Keep RHOBS-1783 open until its authentication-policy API requirement is resolved.
