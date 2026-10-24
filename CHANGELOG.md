# Changelog

Notable changes to RHOBS Auth Gateway are recorded here.

## Unreleased

### Added

- Add a security reporting policy and repository ownership guidance.

### Removed

- Remove built-in attribute-value mapping and its processing ECDS resource,
  ConfigMap, and volume. Supply additional source attributes for different
  upstream values. See the [upgrade steps](docs/envoy.md#upgrading-after-attribute-mapping-removal).

### Fixed

- Keep API-key extraction regexes small as credential attributes are added,
  and reject attribute values larger than Envoy's 8191-byte metadata limit.
  Regenerate the bootstrap and explicitly roll out gateway Deployments.
- Use `kubernetes.name` for gateway selectors so gateways in one namespace
  stay isolated and `node.cluster` changes preserve Deployment selectors.
  Existing Deployments with different instance labels need
  [recreation or replacement](docs/configuration-reference.md#gateway-identity-and-selector-upgrades).
- Keep attributes isolated to the authenticated identity on mixed `any_of`
  servers. Regenerate the bootstrap and explicitly roll out gateway
  Deployments to apply the fix.
