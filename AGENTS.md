# Repository agent guidance

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow, checks,
test ownership, and golden-file updates.

## Design

- This is a greenfield project. Backward compatibility and future versions
  are not current design constraints. Treat the checked-in schema as the
  current contract.
- Keep the schema, `config.example.yaml`, configuration documentation
  including `docs/configuration-reference.md`, generated output, and tests
  aligned.
- Always read the Envoy docs before assuming or guessing.
- Prefer native Envoy filters. Write custom Lua only when no suitable native
  option exists or when Lua reduces overall complexity.
- Use attribute values unchanged from their declared sources. Declare a
  separate source attribute when a different value is needed.
- Static bootstrap changes require an explicit Deployment rollout.

## Development

- Keep reusable Kubernetes test infrastructure in `e2e/internal/framework`.
  Keep scenario fixtures, protocol clients, and assertions in the e2e package.
- Use a consistent receiver style per type, choosing pointer receivers if
  any method requires one.
- Use sandbox escalation from the first attempt for authorized Docker-backed
  checks. Retry sandbox denials with escalation without requesting
  authorization again.
- Write user guides around configuration, client requests, observable
  behavior, and required external resources. Keep technical documentation
  focused on Envoy behavior.
- Work on a feature branch and submit changes through an upstream PR or MR.
  Never push directly to `main`.
- Use concise, natural-language commit messages without emojis.
