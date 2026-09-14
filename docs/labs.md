# Lab Roadmap

Use one lab per working session. Complete labs in order unless a lab explicitly says otherwise. Theory and exercises are separate: study the relevant page in the [Theory Index](theory/index.md), then use the lab guide for Java 21 implementation and failure/attack proof. See the [Learning Model](learning-model.md).

## How to run a session

1. Read the linked theory and inspect the current implementation.
2. Write a failing positive or negative test that states the security behavior.
3. Implement the smallest secure change that makes the test pass.
4. Run the module test, then `./gradlew test`.
5. Update the theory, coverage status, and troubleshooting notes.
6. Record what was verified and select the next incomplete lab.

A lab is complete only when its implementation, positive tests, negative tests, and documentation agree.

## Track A: Spring Security foundations

### LAB-001: Production filter-chain tests

- **Build:** Load the real `MultiAuthSecurityConfig` instead of a test-only chain.
- **Prove:** Public access, anonymous 401, insufficient-role 403, USER access, and ADMIN access.
- **Attack case:** Confirm matcher ordering cannot expose `/api/admin/**`.
- **Done when:** Tests pass against production configuration and `coverage.md` marks request authorization Verified.

### LAB-002: Secure username/password login

- **Build:** Authenticate through `AuthenticationManager` before issuing a token.
- **Prove:** Valid credentials succeed; invalid username and invalid password fail uniformly.
- **Attack case:** Verify arbitrary usernames cannot obtain tokens and responses do not enable account enumeration.
- **Done when:** The existing unauthenticated token-minting behavior is gone.

### LAB-003: Password storage and migration

- **Build:** Use `DelegatingPasswordEncoder` and BCrypt-backed test users.
- **Prove:** Encoded passwords work and plaintext passwords do not.
- **Attack case:** Demonstrate safe upgrade from an older encoding identifier.
- **Done when:** No demo user store depends on plaintext credentials.

### LAB-004: Method security

- **Build:** Enable method security and protect one service with `@PreAuthorize`.
- **Prove:** Allowed role, denied role, and unauthenticated invocation.
- **Attack case:** Call the service outside the controller and confirm the rule still applies.
- **Done when:** Method security is Verified in the coverage registry.

### LAB-005: Security error contract

- **Build:** Add JSON `AuthenticationEntryPoint` and `AccessDeniedHandler` responses.
- **Prove:** Stable 401 and 403 payloads and content types.
- **Attack case:** Confirm errors reveal neither stack traces nor authorization internals.
- **Done when:** API documentation matches executable response assertions.

### LAB-006: Browser sessions and session fixation

- **Build:** Add an isolated form-login session lab.
- **Prove:** Session identifier changes after login and logout invalidates the session.
- **Attack case:** A pre-authentication session identifier cannot be reused after authentication.
- **Done when:** Session lifecycle behavior is documented and tested.

### LAB-007: CSRF protection

- **Build:** Protect a cookie-authenticated state-changing endpoint.
- **Prove:** A valid CSRF token succeeds; missing and invalid tokens fail.
- **Attack case:** Cross-site form submission cannot change state.
- **Done when:** Documentation clearly distinguishes cookie sessions from bearer-token APIs.

### LAB-008: CORS and security headers

- **Build:** Allow one configured origin and add an explicit header policy.
- **Prove:** Allowed preflight succeeds, unknown origin is rejected, and expected headers are present.
- **Attack case:** Credentials are never combined with wildcard origins.
- **Done when:** CORS, CSP, frame, content-type, and transport decisions are documented.

## Track B: OAuth2, OIDC, and token security

### LAB-009: Standard JWT resource server

- **Build:** Replace the primary custom bearer filter with `oauth2ResourceServer().jwt()` in an isolated API path.
- **Prove:** Signed token, scope mapping, issuer, audience, expiry, and not-before checks.
- **Attack case:** Reject wrong issuer, wrong audience, expired token, altered signature, and unsupported algorithm.
- **Done when:** The custom filter is labeled educational rather than recommended.

### LAB-010: Local identity provider

- **Build:** Add a reproducible local IdP configuration with no real credentials.
- **Prove:** Realm or tenant, clients, users, roles, and exported configuration start consistently.
- **Attack case:** Default administrative credentials are not used outside the isolated lab.
- **Done when:** A new learner can start the IdP and obtain a test token from documented commands.

### LAB-011: OAuth2 Authorization Code with PKCE

- **Build:** Configure a browser client against the local IdP.
- **Prove:** Login, callback, state, nonce, and PKCE behavior.
- **Attack case:** Invalid state and invalid authorization response are rejected.
- **Done when:** No client secret is required for the public-client flow.

### LAB-012: OIDC identity and authority mapping

- **Build:** Read ID-token/UserInfo claims and map approved groups to authorities.
- **Prove:** Known groups map correctly and unknown claims grant nothing.
- **Attack case:** A user-controlled claim cannot become an administrative authority.
- **Done when:** OAuth2 authorization and OIDC authentication are explained separately.

### LAB-013: Opaque-token introspection

- **Build:** Add a resource-server profile using introspection.
- **Prove:** Active, inactive, expired, and insufficient-scope tokens.
- **Attack case:** Introspection outage follows the documented fail-closed policy.
- **Done when:** JWT versus opaque-token trade-offs are measured and documented.

### LAB-014: Refresh, revocation, and logout

- **Build:** Demonstrate refresh rotation, revocation, local logout, and provider logout.
- **Prove:** Rotated tokens work and reused or revoked tokens fail.
- **Attack case:** Refresh-token replay is detected or explicitly bounded by provider behavior.
- **Done when:** Browser session and token lifecycle diagrams match the lab.

### LAB-015: JWK rotation and multiple issuers

- **Build:** Rotate signing keys and add explicit trusted-issuer resolution.
- **Prove:** Old/new overlap, unknown `kid`, trusted issuer, and untrusted issuer behavior.
- **Attack case:** The token-controlled issuer cannot select an arbitrary JWK endpoint.
- **Done when:** Rotation and tenant-onboarding runbooks exist.

## Track C: SSO and SAML 2.0

### LAB-016: Two-client OIDC SSO

- **Build:** Register two applications with the local IdP.
- **Prove:** Login to the first app enables IdP-backed access to the second without credentials being re-entered.
- **Attack case:** Logging out locally does not falsely claim to end the IdP session.
- **Done when:** SSO is documented as an outcome rather than a protocol.

### LAB-017: SAML relying party

- **Build:** Add a dedicated SAML service-provider module and local test IdP registration.
- **Prove:** Metadata exchange, signed login response, and authenticated principal.
- **Attack case:** Unsigned or incorrectly signed responses fail.
- **Done when:** The SAML page links to runnable code instead of standalone snippets.

### LAB-018: SAML attributes and authorization

- **Build:** Map allow-listed SAML attributes to application authorities.
- **Prove:** Known attributes grant expected access and missing attributes fail safely.
- **Attack case:** Unexpected assertion attributes cannot grant ADMIN.
- **Done when:** Attribute contracts and ownership are documented.

### LAB-019: SAML assertion validation

- **Build:** Configure audience, recipient, time, request-correlation, and replay validation.
- **Prove:** Valid assertion and permitted clock skew.
- **Attack case:** Wrong audience, wrong recipient, expired assertion, invalid InResponseTo, and replay all fail.
- **Done when:** Every assertion condition has a negative test.

### LAB-020: SAML logout and certificate rollover

- **Build:** Add logout behavior and overlapping signing certificates.
- **Prove:** Local/provider logout expectations and old/new certificate transition.
- **Attack case:** Untrusted rollover certificates are rejected.
- **Done when:** Operational rollover and emergency-replacement instructions exist.

## Track D: Microservice identity and authorization

### LAB-021: Client Credentials service identity

- **Build:** Secure service-to-service calls using scoped machine clients.
- **Prove:** Correct client/scope succeeds; user token and wrong scope fail.
- **Attack case:** One service identity cannot call unrelated privileged endpoints.
- **Done when:** Least-privilege client registration is documented.

### LAB-022: User token relay

- **Build:** Relay an end-user access token through a gateway to a downstream service.
- **Prove:** User identity and scope survive the call.
- **Attack case:** The gateway does not log, persist, or return the bearer token.
- **Done when:** Trust boundaries identify which service authorizes each resource.

### LAB-023: Token exchange and delegation

- **Build:** Exchange an incoming token for a narrower downstream token.
- **Prove:** Actor, subject, audience, and reduced scope.
- **Attack case:** Downstream tokens cannot be replayed against the gateway or another service.
- **Done when:** Relay versus exchange selection guidance exists.

### LAB-024: Gateway and BFF

- **Build:** Keep tokens server-side and give the browser a secure session cookie.
- **Prove:** Login, API call, CSRF protection, logout, and session expiry.
- **Attack case:** JavaScript cannot read tokens and cross-site requests cannot mutate state.
- **Done when:** Cookie attributes and browser threat model are tested.

### LAB-025: mTLS and workload identity

- **Build:** Run two services with mutual certificate authentication.
- **Prove:** Trusted client certificate succeeds and missing/untrusted/expired certificates fail.
- **Attack case:** Possessing an application token alone is insufficient for the mTLS route.
- **Done when:** Issuance, rotation, revocation, and identity mapping are documented.

### LAB-026: API key lifecycle

- **Build:** Issue prefixed keys, store only hashes, support scopes, rotation, and revocation.
- **Prove:** Active key succeeds and revoked/expired/wrong-scope keys fail.
- **Attack case:** Database contents cannot be used directly as credentials.
- **Done when:** Keys never appear in logs or query strings.

### LAB-027: Tenant and object authorization

- **Build:** Enforce tenant and ownership rules below the controller layer.
- **Prove:** Owner, same-tenant non-owner, other tenant, and admin cases.
- **Attack case:** Identifier substitution cannot cross tenant boundaries.
- **Done when:** RBAC, scopes, ownership, and tenancy responsibilities are distinct.

### LAB-028: Rate limits, replay, and failure policy

- **Build:** Add authentication throttling, idempotency/replay controls, and IdP dependency policies.
- **Prove:** Normal load, threshold behavior, recovery, and dependency outage.
- **Attack case:** Brute force and request replay are bounded without global denial of service.
- **Done when:** Fail-open/fail-closed decisions are explicit per endpoint.

## Track E: Protocol-specific security

### LAB-029: GraphQL authorization

- **Build:** Protect queries, mutations, and sensitive fields at resolver/service boundaries.
- **Prove:** Allowed fields, denied fields, and partial-result behavior.
- **Attack case:** Aliases or batching cannot bypass field authorization.
- **Done when:** The placeholder interceptor is removed or replaced.

### LAB-030: GraphQL resource controls

- **Build:** Add depth, complexity, pagination, and batching limits.
- **Prove:** Normal query succeeds and excessive query is rejected predictably.
- **Attack case:** Nested-query and alias amplification are bounded.
- **Done when:** Limits and monitoring signals are documented.

### LAB-031: gRPC authentication and authorization

- **Build:** Add bearer metadata processing and method authorization in interceptors.
- **Prove:** Valid metadata, absent token, invalid token, and wrong scope.
- **Attack case:** Reflection and health endpoints follow explicit exposure rules.
- **Done when:** gRPC status codes do not leak token details.

### LAB-032: gRPC mTLS

- **Build:** Combine transport identity with application authorization.
- **Prove:** Trusted workload and authorized method access.
- **Attack case:** Valid certificate with insufficient application authority is denied.
- **Done when:** Certificate and token identities have a documented relationship.

### LAB-033: WebSocket handshake and destinations

- **Build:** Authenticate the handshake and authorize subscriptions and sends by destination.
- **Prove:** Allowed and denied destinations and unauthenticated connection.
- **Attack case:** A connected user cannot subscribe to another user's private destination.
- **Done when:** Placeholder JWT validation is replaced.

### LAB-034: WebSocket expiry and revocation

- **Build:** Define behavior for token expiry, logout, and authority changes during a connection.
- **Prove:** Re-authentication or disconnect occurs according to policy.
- **Attack case:** A long-lived connection cannot preserve revoked access indefinitely.
- **Done when:** Connection lifecycle is covered by integration tests.

### LAB-035: Asynchronous messaging identity

- **Build:** Propagate minimal identity context through a broker-backed message flow.
- **Prove:** Authorized producer/consumer and correlation for audit.
- **Attack case:** Untrusted message headers cannot impersonate a user or service.
- **Done when:** Broker ACLs and application authorization are separated.

## Track F: Modern authentication

### LAB-036: TOTP enrollment and verification

- **Build:** Replace the hardcoded OTP with secret enrollment and clock-controlled verification.
- **Prove:** Current code succeeds; wrong, expired, and reused codes fail according to policy.
- **Attack case:** Secrets and OTPs never appear in logs.
- **Done when:** The placeholder service is removed.

### LAB-037: Recovery and step-up authentication

- **Build:** Add single-use hashed recovery codes and require recent MFA for a sensitive action.
- **Prove:** Recovery consumption, reuse failure, and step-up freshness.
- **Attack case:** Password-only sessions cannot invoke the sensitive action.
- **Done when:** Recovery is not weaker than the protected account lifecycle.

### LAB-038: WebAuthn/passkeys

- **Build:** Implement local passkey registration and authentication.
- **Prove:** Challenge, origin, RP ID, counter, and user-verification behavior.
- **Attack case:** Wrong origin/RP ID, stale challenge, and cloned-authenticator signals fail.
- **Done when:** Registration, login, credential removal, and recovery are documented.

### LAB-039: Account abuse defenses

- **Build:** Add enumeration-resistant responses, throttling, lockout policy, and security notifications.
- **Prove:** Normal mistakes recover and distributed abuse is observable.
- **Attack case:** Defenses cannot be trivially used to permanently lock out arbitrary users.
- **Done when:** Support and incident procedures accompany the controls.

## Track G: Operations and security assurance

### LAB-040: Secrets and key rotation

- **Build:** Load secrets externally and rotate a signing or client credential without downtime.
- **Prove:** Old/new overlap and post-cutover rejection.
- **Attack case:** Secrets do not enter Git, images, logs, or test reports.
- **Done when:** Routine and emergency rotation runbooks pass.

### LAB-041: Security audit events

- **Build:** Emit structured authentication, authorization, administrative, and key-lifecycle events.
- **Prove:** Success/failure events correlate without containing credentials or full tokens.
- **Attack case:** Log injection and sensitive-claim leakage are prevented.
- **Done when:** Event ownership and retention are documented.

### LAB-042: Security metrics and tracing

- **Build:** Add low-cardinality metrics and trace correlation for security dependencies.
- **Prove:** Denials, invalid tokens, IdP latency, and JWK/introspection failures are visible.
- **Attack case:** Attacker-controlled identifiers do not create metric-cardinality explosions.
- **Done when:** A troubleshooting exercise can identify the failing trust boundary.

### LAB-043: Container hardening

- **Build:** Package a non-root, minimal runtime image with health checks.
- **Prove:** Read-only filesystem where possible, dropped privileges, and reproducible scan.
- **Attack case:** Runtime cannot write to application or credential locations unnecessarily.
- **Done when:** Build and scan commands are automated.

### LAB-044: Kubernetes security

- **Build:** Add service account, secret injection, probes, resource limits, and network policy.
- **Prove:** Required traffic works and unrelated east-west traffic is denied.
- **Attack case:** Default service-account credentials and broad secret access are absent.
- **Done when:** Deployment matches the documented trust-boundary diagram.

### LAB-045: Threat model and abuse cases

- **Build:** Document assets, actors, entry points, trust boundaries, threats, and mitigations for the lab system.
- **Prove:** Every high-risk threat maps to a control and executable test or accepted risk.
- **Attack case:** Include token theft, confused deputy, tenant escape, replay, and IdP outage.
- **Done when:** The threat model drives at least one newly added negative test.

### LAB-046: Incident exercise

- **Build:** Run a scenario involving stolen credentials, suspicious access, or signing-key compromise.
- **Prove:** Detection, containment, revocation, rotation, recovery, and evidence collection.
- **Attack case:** Verify cached credentials and long-lived connections do not escape containment.
- **Done when:** The exercise produces tested runbook corrections.

## Track H: Advanced identity and platform security

### LAB-047: Spring Authorization Server

- **Build:** Add an isolated authorization-server module with registered public, confidential, and machine clients.
- **Prove:** Authorization Code with PKCE, Client Credentials, consent, scopes, issuer metadata, JWK publication, and refresh policy.
- **Attack case:** Reject invalid redirect URIs, public-client secrets, code replay, unsupported grants, and unauthorized scopes.
- **Done when:** Client registration, signing-key rotation, persistence, and deployment boundaries are documented and integration-tested.

### LAB-048: SCIM identity lifecycle

- **Build:** Add a SCIM-style provisioning adapter or test fixture for users, groups, activation, and deactivation.
- **Prove:** Idempotent create/update, approved group mapping, deactivation, and removal of active sessions or access.
- **Attack case:** Replayed events, stale group membership, unauthorized provisioning clients, and attribute over-posting cannot grant access.
- **Done when:** Provisioning, just-in-time creation, deprovisioning, ownership, and reconciliation behavior are documented.

### LAB-049: Active Directory and LDAPS

- **Build:** Add an LDAPS-backed profile with certificate validation and Active Directory-compatible identity/group mapping.
- **Prove:** Trusted TLS, successful bind, nested or approved group mapping, disabled user behavior, and connection failure handling.
- **Attack case:** Plain LDAP, untrusted certificates, referral abuse, and unexpected groups cannot authenticate or escalate privileges.
- **Done when:** Trust-store rotation, directory outage, search-base, timeout, and least-privilege bind guidance are tested.

### LAB-050: X.509 and certificate-bound identity

- **Build:** Authenticate a client certificate and map its verified identity to a constrained application principal.
- **Prove:** Trusted chain, expected subject/SAN, authorized certificate, expiration, and revocation policy behavior.
- **Attack case:** Self-signed, wrong-issuer, wrong-SAN, expired, and token-only callers fail on certificate-bound routes.
- **Done when:** Proxy certificate forwarding, trust boundaries, issuance, revocation, and rotation are explicit.

### LAB-051: Reactive WebFlux security

- **Build:** Add a small WebFlux service using `SecurityWebFilterChain`, reactive method security, and a reactive resource server.
- **Prove:** Anonymous, authenticated, insufficient-scope, method-level, CSRF/CORS where applicable, and Reactor-context propagation cases.
- **Attack case:** Blocking identity lookup, lost context across operators, and untrusted forwarded identity cannot bypass authorization.
- **Done when:** Servlet and reactive security lifecycles are compared with executable tests.

### LAB-052: Spring Cloud Gateway token relay

- **Build:** Add an isolated gateway that authenticates users and relays or exchanges tokens only to approved downstream routes.
- **Prove:** Route authorization, audience/scope preservation, header sanitization, timeout, logout, and downstream denial behavior.
- **Attack case:** Clients cannot inject identity headers, choose arbitrary token audiences, or relay tokens to unintended hosts.
- **Done when:** Gateway versus downstream authorization responsibilities and failure policies are tested.

### LAB-053: External authorization policy

- **Build:** Separate a policy decision point from application policy enforcement for one tenant/object decision.
- **Prove:** Allow, deny, missing attributes, policy version change, timeout, and cache invalidation behavior.
- **Attack case:** Stale cached allows, client-supplied attributes, policy outage, and decision tampering fail according to policy.
- **Done when:** Local method rules versus external policy trade-offs, auditability, and fail-closed boundaries are documented.

### LAB-054: Multi-tenant federation

- **Build:** Resolve trusted tenant-specific OIDC issuers or SAML relying-party registrations from server-controlled configuration.
- **Prove:** Two valid tenants, tenant-specific authorities/keys, unknown tenant, tenant removal, and configuration rotation.
- **Attack case:** Host, path, email-domain, or token-controlled issuer input cannot select an arbitrary metadata/JWK endpoint or cross tenant caches.
- **Done when:** Tenant discovery, onboarding, offboarding, data/cache isolation, and incident containment are integration-tested.

### LAB-055: Kafka identity and authorization

- **Build:** Secure a broker-backed producer and consumer with workload identity, topic ACLs, schema validation, and tenant-aware message handling.
- **Prove:** Authorized produce/consume, denied topic, identity rotation, dead-letter handling, and auditable correlation.
- **Attack case:** Forged headers, replayed messages, oversized payloads, and cross-tenant events cannot impersonate or escape isolation.
- **Done when:** Broker ACLs, application authorization, idempotency, replay policy, and secret rotation are distinct and tested.

### LAB-056: Build supply chain and SBOM

- **Build:** Add Gradle dependency locking/verification, an SBOM, vulnerability scanning, and signed or attestable build output.
- **Prove:** Reproducible dependency resolution, approved checksum changes, SBOM generation, and CI failure on a controlled policy violation.
- **Attack case:** Dependency substitution, mutable versions, leaked CI credentials, and untrusted pull-request publishing are prevented.
- **Done when:** Upgrade, exception, provenance, artifact signing, and emergency patch procedures are documented.

### LAB-057: Data protection and safe diagnostics

- **Build:** Classify sensitive fields, apply envelope or field-level encryption to one record, and add centralized log redaction.
- **Prove:** Authorized decrypt, unauthorized denial, key rotation, backup/restore behavior, and redacted HTTP/security diagnostics.
- **Attack case:** Tokens, assertions, cookies, credentials, private keys, and sensitive identity data cannot enter logs, caches, or error responses.
- **Done when:** Key ownership, retention, deletion, backup encryption, and privacy-safe troubleshooting are tested.

### LAB-058: API and proxy abuse defenses

- **Build:** Add bounded request/body/upload handling, trusted forwarded-header configuration, SSRF controls, redirect allow lists, and ownership-aware idempotency.
- **Prove:** Valid proxy traffic and normal payloads succeed while limits produce stable, observable errors.
- **Attack case:** Host-header poisoning, open redirect, SSRF, mass assignment, oversized payload, malicious upload, and stolen idempotency key fail safely.
- **Done when:** Application, gateway, ingress, and service-mesh responsibilities are documented with negative integration tests.

## Optional specialist extensions

After LAB-058, add focused labs only when relevant to the target environment: Kerberos/SPNEGO, OAuth Device Authorization Grant, CIBA, PAR/JAR/JARM, DPoP, certificate-bound OAuth tokens, financial-grade API profiles, RSocket security, and cloud-provider workload identity.

## Session handoff template

At the end of each session, record:

```text
Lab:
Status: Planned | Theory | Implemented | Verified | Operational
Implemented:
Tests added:
Commands run:
Security behavior proved:
Known limitations:
Documentation updated:
Next lab:
```
