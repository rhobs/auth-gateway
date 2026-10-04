# API-key implementation handover

The gateway now accepts API keys from one Kubernetes Secret per gateway configuration, in the gateway's namespace. One named `api_key` authenticator declares the Secret name, optional header (default `X-API-Key`), and allowed attribute names. Every server selecting it uses the same complete credential set. Separate gateway namespaces can use the same Secret name with independent data. Keys and per-key attribute values stay outside the gateway configuration and generated ConfigMaps.

## Runtime contract

- `config.APIKeySecret` builds an external Secret with one `api-keys.yaml` ECDS resource. `examples/generate-api-key-secret` reads a strict `credentials:` YAML document and writes a private Secret manifest. A complete replacement rotates keys; `credentials: []` revokes all keys. Provision the Secret before the Deployment.
- Envoy loads `api_key_auth` through file ECDS from a directory-mounted Secret, with no `subPath`. The native filter validates the configured header and sends a verified, encoded identity through an internal header. `header_to_metadata` decodes it and removes the header. Request controls strip spoofed internal identity headers first. Credential cleanup strips bearer tokens and key headers before upstream forwarding, including on public chains.
- Authorization grants read original key attributes from dynamic metadata with exact string matching. Host-scoped `set_filter_state` filters copy verified JWT or key attributes into working state. The separate `processing.yaml` ECDS resource applies mappings; route headers and request metric labels read the resulting values. The existing stats-only Lua response filter remains, with no new Lua for authentication.
- Mixed `authentication.any_of` is JWT-first: a valid JWT skips key validation and owns authorization, even if a key is present. An absent or failed JWT may fall back to a valid key. Mixed `all_of` requires both credentials and exact, nonempty scalar equality for every attribute declared by both authenticators. A valid but unauthorized identity returns `403`; missing or invalid credentials return `401`.

## Code and update boundaries

| Area | Files | Contract |
| --- | --- | --- |
| Schema and validation | `config/auth.go`, `config/config.go`, `config/request_metrics.go` | One API-key authenticator per configuration; safe header and attribute names; grants and metric labels can reference key attributes. Mixed `all_of` permits at most one JWT, and permissive shared HTTP chains reject duplicate JWT issuers. |
| Secret generation | `config/api_keys.go`, `examples/generate-api-key-secret` | Credentials are validated, sorted, and packed into one ECDS resource. The generated Secret is external to `GenerateKubernetes`. |
| Envoy filters | `config/api_keys_generate.go`, `config/generate.go` | JWT marker and API-key skip matcher, metadata extraction, authentication RBAC, raw-attribute grants and equality, per-host working attributes, mapping ECDS, and credential removal. JWT-only output retains its existing layout. |
| Kubernetes | `config/kubernetes.go` | One projected Secret volume and one read-only directory mount, shared by all servers in that gateway. |

Changing key values or their attribute values requires only a Secret update. Changing mapping values requires only the `<name>-processing` ConfigMap update. Invalid ECDS updates retain the last accepted configuration, so revocation must use a valid empty credential list. Routes, authenticator definitions, policy grants, metric bindings, and other bootstrap changes require regeneration and an explicit Deployment rollout. There is no checksum annotation.

## Verification

`config/testdata/api-key-auth` covers generated Envoy and Kubernetes output. Unit tests cover strict loading, defaults, validation, ECDS content, filter order, raw RBAC, mapping separation, and the single Secret mount. The pinned Envoy runtime test validates the generated files. `e2e/api_keys_test.go` uses isolated namespaces to check shared and independent Secrets, key-only and mixed `any_of`/`all_of`, JWT-first behavior, spoofing, denied upstream traffic, mapped headers and metrics, mapping reload, rotation, malformed-update retention, and empty-list revocation.

Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md), including `make test`, `make lint`, `make test-runtime`, and the full `make e2e` suite, after any follow-up change.
