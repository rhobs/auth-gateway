# Authentication and authorization

The gateway supports [JWT](jwt.md), [API keys](api-key.md), and
[client-certificate mTLS](mtls.md). Each method page explains how credentials
are checked and how to grant access. [config.example.yaml](../../config.example.yaml)
shows a full configuration. A server without `authentication` is public.

## Authentication

Define named methods in `authenticators`, then select them on each server
with `authentication.any_of` or `authentication.all_of`. `any_of` accepts a
request when any selected method succeeds; `all_of` requires every selected
method to succeed. A gateway can define multiple JWT and mTLS authenticators
but only one API-key authenticator. Each HTTPS server can select at most one
mTLS authenticator.

For mixed `any_of`, a verified JWT takes precedence over a verified client
certificate, which takes precedence over an API key. A missing or invalid JWT
can fall through to the next method. An authenticated identity without a grant
is denied; authorization does not fall back to a lower-priority method. On
mixed mTLS servers, a connection without a client certificate can use another
method, but an untrusted client certificate fails the TLS handshake.

Mixed `all_of` requires every selected credential and equal, nonempty raw
values for each attribute declared by more than one method. It supports at
most one JWT, one mTLS authenticator, and one API key.

## Authorization

Define grants in `authorization_policies`, then select policies on the
server with `authorization.any_of` (one policy must grant access) or
`authorization.all_of` (every policy must grant access). Each grant names
an authenticator, one or more APIs, and allowed attribute values. All
attributes in a grant must match; one allowed value is enough for each
attribute. An mTLS grant may have no attribute conditions and then accepts
any certificate trusted by its configured CA. A protected server needs a
matching authorization grant to forward an API request.

Declare attributes beside `jwt`, `api_key`, or `mtls`. JWT attributes can read
a verified claim or an incoming header. API-key attributes can read a value
bound to the key in the Secret or an incoming header. mTLS attributes can
read a verified URI SAN, DNS SAN, or incoming header. A grant checks the
original value from the declared source. A header value comes from the caller,
but the named authenticator must still succeed before its grant applies.
Missing or empty headers leave the attribute unset. Mappings affect forwarding
and metric labels, not grants. A source header normally reaches the backend;
if it is also a managed output header, the gateway replaces or removes it.

Changes to attribute sources, authenticators, or policies require regenerating
the static configuration and explicitly rolling out the gateway Deployment.
