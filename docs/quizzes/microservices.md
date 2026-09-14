# Senior Quiz: Microservice Security

<quiz>
A gateway authenticates a user and forwards `X-User: alice` to every service. When is a downstream service allowed to trust this header?

- [ ] Whenever the header is present
- [ ] Whenever traffic is inside the cluster
- [x] Only when the service can authenticate the trusted gateway path, strips client-supplied copies, and the architecture explicitly accepts this identity propagation model
- [ ] When CORS allows the frontend origin

Network location is not identity. Prefer verifiable tokens or workload identity; if trusted headers are used, authenticate the intermediary and prevent direct or injected access.
</quiz>

<quiz>
When is token exchange preferable to direct user-token relay?

- [x] The downstream service needs a narrower audience or scope
- [x] Actor and subject delegation must be represented
- [x] The original token should not be replayable across all internal services
- [ ] The gateway wants a longer-lived token with every privilege

Exchange can constrain delegation and reduce blast radius. It is not a mechanism for silently amplifying privilege or lifetime.
</quiz>

<quiz>
A service uses Client Credentials to call inventory on behalf of a user. What identity information is lost unless explicitly modeled?

- [x] The end-user subject and delegation context
- [ ] The service workload identity
- [ ] The TLS server identity
- [ ] The OAuth client identifier

Client Credentials represents the client itself. If a decision depends on the user, use a designed delegation mechanism rather than inserting an unverified username header.
</quiz>

<quiz>
What does mTLS prove by itself?

- [x] The peer possesses a private key corresponding to a certificate trusted under the configured policy
- [ ] The end user authorized the business operation
- [ ] Every method is permitted
- [ ] The request cannot be replayed at the application layer

Transport or workload identity does not replace endpoint, scope, tenant, ownership, or replay authorization.
</quiz>

<quiz>
A multi-tenant resource server reads `iss` from an unverified JWT and dynamically downloads metadata from that URL. What are the primary risks?

- [x] SSRF
- [x] Acceptance of an untrusted issuer
- [x] Cross-tenant key or cache confusion
- [ ] CSRF is the only concern

Tenant and issuer resolution must start from server-controlled trusted configuration. Parse unverified data only to select among an allow-listed set, never to create trust dynamically.
</quiz>

<quiz>
An API key database stores raw keys so support can show customers their key later. Which design is safer?

- [x] Show the secret once, store a one-way hash, and retain a non-secret prefix/identifier
- [x] Support scoped keys, expiration, rotation, and revocation
- [x] Prevent keys from entering URLs and logs
- [ ] Base64-encode keys before storing them

API keys should be handled like passwords. Recoverability increases breach impact; a prefix supports lookup and operations without storing the credential.
</quiz>

<quiz>
Where should tenant and object ownership authorization occur?

- [ ] Only at the gateway
- [x] In or below the resource-owning service, with gateway checks as optional defense in depth
- [ ] Only in the frontend
- [ ] In the identity provider for every database row

The service with authoritative resource context must enforce the decision. Gateways generally lack current ownership and domain state.
</quiz>

<quiz>
A WebSocket authenticates once during connection and remains active for seven days after the user's access is revoked. Which controls are defensible?

- [x] Bound connection or authentication lifetime
- [x] Reauthorize sensitive destinations/messages
- [x] Disconnect or refresh on expiry/revocation according to policy
- [x] Test private-destination isolation
- [ ] Treat a successful handshake as permanent authorization

Long-lived protocols require explicit expiry, revocation, destination authorization, and authority-change behavior.
</quiz>
