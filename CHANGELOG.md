# Changelog

Notable changes to RHOBS Auth Gateway are recorded here.

## Unreleased

### Added

- Add a security reporting policy and repository ownership guidance.

### Fixed

- Keep attributes isolated to the authenticated identity on mixed `any_of`
  servers. Regenerate the bootstrap and explicitly roll out gateway
  Deployments to apply the fix.
