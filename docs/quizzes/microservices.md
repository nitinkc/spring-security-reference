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

<quiz>
An API key is a 64-character random secret. Which storage and handling choices reduce breach impact?

- [x] Store a one-way hash plus a non-secret prefix for lookup
- [x] Scope keys to a small set of endpoints and rotate them regularly
- [x] Enforce per-key rate limits and revoke on anomalous usage
- [ ] Log the full key in access and error logs for debugging

API keys are long-lived credentials. Treat them like passwords: hash the stored value, limit scope, rotate, and never log the secret.
</quiz>

<quiz>
A Spring application defines one filter chain with `.anyRequest().authenticated()` and no `securityMatcher`, then later defines another chain for `/mtls/**`. Why does Spring Security reject this?

- [x] The first chain already matches every request, so the second chain can never run
- [ ] Chains must use the same authentication type
- [ ] The order is ignored for `SecurityFilterChain` beans
- [ ] `/mtls/**` must be a top-level path

A catch-all `anyRequest` chain should be published last, or each chain should be scoped with `securityMatcher` to a specific request set. Otherwise more specific chains become unreachable.
</quiz>

<quiz>
A downstream service receives a token with an `act` claim identifying the caller as `support-tool`. Under what condition may it treat the request as delegated access on behalf of the token's subject?

- [x] The token signature is valid and `support-tool` is on the resource server's explicit trusted-actor allow-list
- [ ] The `act` claim is present, regardless of its value
- [ ] The caller's IP address is inside the corporate network
- [ ] The request includes an `X-Acting-As` header matching the claim

Delegation must be based on verified, signed claims checked against an explicit trust decision — not on the mere presence of a claim or an unauthenticated header.
</quiz>

<quiz>
A multi-tenant resource server needs to validate tokens from many customers. Which design enforces isolation?

- [x] Select the tenant's JWK set from a claim inside the signed token before verification
- [x] Reject tokens signed with a different tenant's key even if the `tenant` claim is forged
- [x] Scope every data query using the tenant from the authenticated token
- [ ] Trust the `X-Tenant-Id` header and skip tenant-specific key checks

Tenant identity must come from a verified token, and the right trust material must be selected before the signature is validated.
</quiz>

<quiz>
An API key service stores `SHA-256(prefix + secret)` and a per-key salt. Why is this safer than storing the full key?

- [x] A database leak exposes hashes and salts, not reusable credentials
- [x] An attacker must still recover the original secret from the hash
- [x] The prefix can be logged or shown in support tools without leaking the credential
- [ ] The salt is the only value that needs to stay secret

The salt defends precomputed rainbow attacks but is not itself a secret. Security comes from not storing the original credential and from using a slow, salted hash.
</quiz>

<quiz>
An authenticated user in `tenant-a` tries to read a document owned by another `tenant-a` user. What should the resource server do?

- [x] Reject the request because the user's subject does not match the document's `owner`
- [x] Allow the read if the user has a `tenant-a` `ADMIN` role
- [ ] Reject the request only when the `tenant` claim does not match
- [ ] Allow the read because the tenant already matches

Object authorization enforces ownership within a tenant. Same-tenant administrators may be granted an override, but ordinary users cannot access each other's objects.
</quiz>

<quiz>
A GraphQL resolver for `salary` is protected with `@PreAuthorize("hasRole('ADMIN')")`, but the HTTP endpoint is `permitAll`. What happens when a non-admin user requests `me { name salary }`?

- [x] The `me.name` field returns and `me.salary` returns `null` with an error in `errors`
- [ ] The entire HTTP response is 403
- [ ] The `salary` field silently returns `null` with no error
- [ ] The query is blocked at the GraphQL parser before any resolver runs

Field-level method security isolates the denial to the protected field. Other fields still resolve, and the client sees the error in the GraphQL `errors` array.
</quiz>

<quiz>
A gRPC server receives a call with a valid TLS session but no client certificate. What should the server do?

- [x] Reject the call because it cannot verify the caller's identity
- [ ] Accept the call because TLS is already protecting the transport
- [ ] Accept the call and trust the `x-user-id` metadata value
- [ ] Accept the call if the peer IP is inside the data center

mTLS requires the client to present a certificate. A TLS-only transport protects confidentiality but does not authenticate the caller.
</quiz>
