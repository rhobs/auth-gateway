# Changelog

Notable changes to RHOBS Auth Gateway are recorded here.

## Unreleased

### Added

- Add a security reporting policy and repository ownership guidance.

### Fixed

- Use `kubernetes.name` for gateway selectors so gateways in one namespace
  stay isolated and `node.cluster` changes preserve Deployment selectors.
  Existing Deployments with different instance labels need
  [recreation or replacement](docs/configuration-reference.md#gateway-identity-and-selector-upgrades).
- Keep attributes isolated to the authenticated identity on mixed `any_of`
  servers. Regenerate the bootstrap and explicitly roll out gateway
  Deployments to apply the fix.
