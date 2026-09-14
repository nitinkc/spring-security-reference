# Learning Path

This path targets practical day-to-day competence. Study concepts from the [Theory Index](theory/index.md), then complete the corresponding exercise from the [Lab Roadmap](labs.md). A topic is complete only when its lab passes.

## Status model

| Status | Meaning |
|---|---|
| Planned | Scope exists but no teaching material |
| Theory | Concepts exist without runnable proof |
| Implemented | Runnable code exists |
| Verified | Positive and negative automated tests pass |
| Operational | Deployment, observation, rotation, and failure handling are covered |

## 1. Foundations

Learn the filter chain, `SecurityContext`, authentication providers, password encoding, request authorization, method security, sessions, CSRF, CORS, headers, security errors, and testing.

Outcome: explain a 401 versus 403, safely secure browser and stateless API traffic, and prove rules with MockMvc.

## 2. OAuth2 and OpenID Connect

Learn Authorization Code with PKCE, OIDC login, JWT resource servers, opaque tokens, scopes, claims-to-authority mapping, refresh and revocation, JWK rotation, issuer/audience validation, and logout.

Outcome: integrate an application and API with a local identity provider without writing a custom bearer-token filter.

## 3. SSO and SAML 2.0

Learn SSO as an outcome, compare OIDC and SAML, configure a SAML relying party, exchange metadata, map attributes, validate signatures and assertion conditions, perform logout, and rotate certificates.

Outcome: diagnose metadata, clock-skew, audience, signature, role-mapping, and logout failures.

## 4. Microservice security

Learn gateway and BFF boundaries, Client Credentials, user-token relay, token exchange, workload identity, mTLS, API keys, tenant and ownership authorization, rate limits, replay protection, and fail-closed behavior.

Outcome: choose and operate user delegation and workload identity without creating a confused deputy.

## 5. Protocol security

Secure REST, GraphQL, gRPC, WebSocket, and asynchronous messaging. Cover field or method authorization, resource limits, metadata and handshake authentication, TLS, destination authorization, and long-lived connection expiry.

Outcome: apply identity consistently while respecting each protocol's lifecycle.

## 6. Modern authentication

Implement TOTP enrollment, recovery codes, step-up authentication, WebAuthn/passkeys, lockout, and credential-stuffing defenses.

Outcome: add phishing-resistant or layered authentication without unsafe recovery paths.

## 7. Operations

Learn secret injection and rotation, audit events, privacy-safe logs, metrics and tracing, container and Kubernetes controls, dependency scanning, threat modeling, incident exercises, and identity-provider outage behavior.

Outcome: deploy, monitor, rotate, investigate, and recover a secured service.

## 8. Advanced identity and platform security

Build and operate an authorization server, SCIM lifecycle integration, Active Directory over LDAPS, X.509 authentication, reactive WebFlux security, Spring Cloud Gateway token relay, external authorization policy, multi-tenant federation, Kafka security, supply-chain verification, data protection, and API/proxy abuse defenses.

Outcome: understand the identity lifecycle and platform controls surrounding Spring Security, not only application filter configuration. Complete LAB-047 through LAB-058 after the foundation and operational tracks.

Optional specialist extensions include Kerberos/SPNEGO, Device Authorization Grant, CIBA, PAR/JAR/JARM, DPoP, certificate-bound OAuth tokens, financial-grade APIs, RSocket, and cloud-provider workload identity.

## Senior assessments

After each major track, complete the matching [Senior Security Assessment](quizzes/index.md). The quizzes focus on production ambiguity, failure modes, protocol boundaries, and attack paths. Target at least 85% twice on different days and be able to explain why every rejected option is unsafe or incomplete.

- [Spring Security internals](quizzes/fundamentals.md)
- [SSO and federation](quizzes/federation.md)
- [Microservice security](quizzes/microservices.md)
- [Operations and architecture](quizzes/operations.md)

## Lab completion checklist

- The threat and trust boundary are stated.
- The code runs without real external credentials.
- Positive and negative tests are automated.
- At least one realistic abuse case is demonstrated safely.
- Logs do not expose credentials, tokens, or personal data.
- Key rotation and dependency failure behavior are explained where relevant.
- The documentation links to the exact implementation and tests.
