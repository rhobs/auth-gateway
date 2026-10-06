# Authentication and authorization

The gateway supports [JWT](jwt.md) and [API keys](api-key.md). Each method
page explains how credentials are checked and how to grant access.
[config.auth.example.yaml](../../config.auth.example.yaml) shows complete
JWT, API-key, and mixed server configurations. A server without
`authentication` is public. Client-certificate mTLS is not supported yet.

## Authentication

Define named methods in `authenticators`, then select them on each server
with `authentication.any_of` (accept one) or `authentication.all_of`
(require every selected method). A gateway can define multiple JWT
authenticators but only one API-key authenticator.

For a mixed JWT and API-key `any_of` server, a valid JWT takes precedence
when both credentials are sent. If the JWT is absent or fails verification,
a valid key can authenticate. A valid JWT without a grant is denied;
authorization does not fall back to the key. Mixed `all_of` requires both
credentials and equal, nonempty scalar strings for every attribute declared
by both methods. It supports at most one JWT and one API key.

## Authorization

Define grants in `authorization_policies`, then select policies on the
server with `authorization.any_of` (one policy must grant access) or
`authorization.all_of` (every policy must grant access). Each grant names
an authenticator, one or more APIs, and allowed attribute values. All
attributes in a grant must match; one allowed value is enough for each
attribute. A protected server needs a matching authorization grant to
forward an API request.

Authorization checks original verified JWT claims or API-key attributes.
Attribute mappings and caller-supplied headers cannot change a grant.
Changes to authenticators or policies require regenerating the static
configuration and explicitly rolling out the gateway Deployment.
