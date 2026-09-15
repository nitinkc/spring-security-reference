# Project Progress and Resume Point

This is the single canonical progress record. Update it at the end of every implementation session. The Coverage Registry tracks capability maturity; this page tracks execution order and the exact resume point.

## Resume here

- **Next lab:** LAB-031 — WebSocket Security
- **Theory page to create:** `docs/theory/websocket-security.md`
- **Lab guide to create:** `docs/tutorials/lab-031-websocket-security.md`
- **Primary implementation area:** `websocket-service` module, handshake and destination authorization
- **Last verified lab:** LAB-030 — gRPC Security
- **Numbering note:** the lab sequence implemented in this repository (starting at LAB-021) diverged from the original numbering in `docs/labs.md` (LAB-021 Client Credentials, LAB-025 mTLS, LAB-026 API key lifecycle, etc.) in an earlier session. This progress file is the canonical sequence; `docs/labs.md` retains the original acceptance-criteria descriptions but its numbers should not be assumed to match. LAB-026 here maps to the roadmap's "API key lifecycle" scenario, closing the hashing/rotation gap flagged in LAB-022.

Copy this prompt into a future session:

```text
Resume the Spring Security curriculum from docs/progress.md. Implement the listed next lab using Java 21 and the separate theory/lab/quiz contracts in AGENTS.md. Start with a failing test, update production code, run focused and full verification, update docs/coverage.md, then advance docs/progress.md only after all checks pass.
```

## Completed labs

| Lab | Status | Executable evidence | Documentation |
|---|---|---|---|
| LAB-001 Request Authorization | Verified | `RequestAuthorizationLabTest` loads `MultiAuthSecurityConfig` | `theory/request-authorization.md`, `tutorials/lab-001-request-authorization.md` |
| LAB-002 Secure Login | Verified | `LoginAuthenticationLabTest` proves authentication before JWT issuance | `theory/authentication-providers.md`, `tutorials/lab-002-secure-login.md` |
| LAB-003 Password Storage | Verified | `AuthServicePasswordMigrationLabTest` proves encoding and migration | `theory/password-storage.md`, `tutorials/lab-003-password-storage.md` |
| LAB-004 Method Security | Verified | `AuthorizationServiceMethodSecurityLabTest` invokes the Spring proxy | `theory/method-security.md`, `tutorials/lab-004-method-security.md` |
| LAB-005 Security Errors | Verified | Exact production-chain JSON 401/403 assertions | `theory/security-errors.md`, `tutorials/lab-005-security-errors.md` |
| LAB-006 Browser Sessions | Verified | `BrowserSessionLabTest` proves identifier rotation and logout invalidation | `theory/browser-sessions.md`, `tutorials/lab-006-browser-sessions.md` |
| LAB-007 CSRF | Verified | `BrowserCsrfLabTest` proves token-required state changes | `theory/csrf.md`, `tutorials/lab-007-csrf.md` |
| LAB-008 CORS and Headers | Verified | `BrowserCorsHeadersLabTest` proves origin policy and hardened headers | `theory/cors-and-headers.md`, `tutorials/lab-008-cors-and-headers.md` |
| LAB-009 JWT Resource Server | Verified | `ResourceServerJwtLabTest` proves signature, issuer, audience, expiry, and authority checks | `theory/jwt-resource-server.md`, `tutorials/lab-009-jwt-resource-server.md` |
| LAB-010 Local Identity Provider | Implemented, not yet executed | `infrastructure/idp/*` and `LocalIdentityProviderLabTest` (5 scenarios skip without Docker) | `theory/identity-provider.md`, `tutorials/lab-010-local-identity-provider.md` |
| LAB-011 Authorization Code with PKCE | Implemented (configuration unit-tested) | `OAuth2AuthConfig`, `OAuth2LoginConfigurationTest` | End-to-end browser login with the local IdP |
| LAB-012 Token Lifecycle | Implemented (opt-in, not yet executed) | `TokenLifecycleLabTest` in `rest-api` (5 scenarios skip without Docker) | Run with Docker to move to Verified |
| LAB-013 Opaque Token Introspection | Verified | `OpaqueToken*LabTest` in `rest-api` | Replace in-process introspector with `NimbusOpaqueTokenIntrospector` against a real IdP |
| LAB-014 Service-to-Service | Implemented (configuration unit-tested) | `ClientCredentialsConfig`, `ClientCredentialsLabTest` | End-to-end token exchange and `RestClient` propagation with Docker |
| LAB-015 JWK Rotation | Verified | `JwkLabKeyProvider`, `ResourceServerSecurityConfig` | Multi-tenant issuer resolver and JWK discovery |
| LAB-016 API Gateway | Verified | `gateway` module, `GatewayConfig`, `GatewayLabTest` | Spring Cloud Gateway with token relay, rate limiting, and real downstream proxy |
|| LAB-017 SAML Relying Party | Verified | `saml-auth` module, `SamlAuthConfig`, `SamlRelyingPartyLabTest` | Local metadata, signed/unsigned assertion, and attribute mapping labs |

|| LAB-019 Token Exchange | Verified | `TokenExchangeConfig`, `TokenExchangeLabTest` | BFF, downstream audience, and end-to-end delegation |
|| LAB-020 BFF Token Handling | Verified | `BffTokenConfig`, `BffTokenController`, `BffTokenLabTest` | Real IdP login, session cookie attributes, and downstream call |
|| LAB-021 Service Identity and mTLS | Verified | `MtlsAuthConfig`, `MtlsController`, `MtlsLabTest` | Real TLS listener, certificate rotation, and revocation checks |
|| LAB-022 API Keys and Resource Quotas | Verified | `ApiKeyAuthConfig`, `ApiKeyAuthenticationFilter`, `ApiKeysAndQuotasLabTest` | Hashed key storage, vault-backed rotation, and distributed rate limits |
|| LAB-023 Multi-Tenancy and Tenant Isolation | Verified | `TenantAwareJwtDecoder`, `TenantJwkLabKeyProvider`, `TenantLabTest` | Trusted issuer directory, key rotation, and row-level data scoping |
|| LAB-024 Resilience and Security Outages | Verified | `ResilientOpaqueTokenIntrospector`, `DependencyOutageSimulator`, `ResilienceLabTest` | Real circuit breaker, distributed cache, and outage alerting |
|| LAB-025 Delegated Access and Actor Tokens | Verified | `ActorAllowListValidator`, `DelegatedAccessSecurityConfig`, `DelegatedAccessLabTest` | Nested `act.act` chains and actor-specific scope restriction |
|| LAB-026 API Key Lifecycle | Verified | `SecureApiKeyService`, `SecureApiKeyLifecycleConfig`, `ApiKeyLifecycleLabTest` | Vault-backed rotation, audit, and bcrypt/Argon2 for high-sensitivity keys |
|| LAB-027 Tenant and Object Authorization | Verified | `TenantObjectService`, `TenantObjectSecurityConfig`, `TenantObjectAuthorizationLabTest` | Per-tenant schema, row-level security, and encrypted data at rest |
||| LAB-028 Rate Limiting and Failure Policies | Verified | `RateLimitingService`, `RateLimitingFilter`, `RateLimitingLabTest` | Distributed bucket, gateway-level limits, and policy engine |
||| LAB-029 GraphQL Security | Verified | `GraphQLConfig`, `GraphQLController`, `GraphQLSecurityLabTest` | DataLoader, N+1, introspection lockdown, and owner-based field checks |
||| LAB-030 gRPC Security | Verified | `GrpcAuthInterceptor`, `GrpcMtlsInterceptor`, `GrpcSecurityLabTest` | Netty TLS, CA trust, and token introspection | | Verified | `RateLimitingService`, `RateLimitingFilter`, `RateLimitingLabTest` | Distributed bucket, gateway-level limits, and policy engine |
|| LAB-018 OIDC SSO | Verified | `OidcAuthoritiesMapper`, `CustomOidcUserService`, `OidcAuthoritiesMapperTest` | End-to-end login and userInfo integration with the local IdP |
## Remaining sequence

- **LAB-031 through LAB-035:** WebSocket, asynchronous messaging
- **LAB-036 through LAB-039:** TOTP, recovery, step-up, passkeys, account-abuse defense
- **LAB-040 through LAB-046:** Rotation, auditing, observability, containers, Kubernetes, threat model, incidents
- **LAB-047 through LAB-058:** Authorization server, SCIM, AD/LDAPS, X.509, WebFlux, gateway, policy, federation, Kafka, supply chain, data protection, proxy/API defense

The detailed acceptance criteria remain in the [Lab Roadmap](labs.md).

## Current architecture decisions

- Java 21 and Spring Boot are canonical.
- Gradle is the only supported Java build.
- Theory, labs, and assessments are separate documentation artifacts.
- Production code and executable tests are the source of truth.
- Advanced capabilities stay Planned or Theory until their Spring implementation and negative tests pass.
- Framework-neutral concepts lead to concrete Spring APIs; FastAPI/Node.js appear only as brief transfer comparisons.

## Current known limitations

- The custom JWT utility uses a process-local symmetric key and an older JJWT API. LAB-009 established the standard resource server as the recommended path; the custom filter remains only as an educational example and still guards `/api/**`.
- The LAB-009 resource server generates its RSA key pair in-process, so it has no real issuer, discovery endpoint, or key rotation yet; LAB-010 supplies a real IdP.
- LAB-010 and LAB-011 configuration is present and compiles, but end-to-end verification requires Docker.
- The LAB-010 realm enables the password grant purely to make token retrieval scriptable; LAB-011 uses the proper Authorization Code flow.
- OIDC SSO and SAML modules remain non-runnable.
- Browser session, CSRF, and CORS behavior are verified only for the isolated `/browser/**` chain with in-memory demo users; cookie attributes, timeouts, and HSTS remain open.
- `BrowserSecurityConfig` uses a `DaoAuthenticationProvider` API that the compiler reports as deprecated; scheduled for the maintenance step.
- JDBC and LDAP implementations need dedicated integration tests.
- GraphQL, gRPC, and WebSocket security remain incomplete.
- Most labs after LAB-005 are backlog definitions, not implementations.
- The build reports dependency/plugin deprecations that should be handled in a dedicated maintenance step without weakening controls.

## Verification baseline

Run with Java 21. If the default `java` on this machine is a newer release, set `JAVA_HOME` explicitly:

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
./gradlew test
uv run --with-requirements requirements.txt mkdocs build --strict
git diff --check
```

Last known result:

```text
Gradle test suite: passed
Strict MkDocs build: passed
git diff --check: passed
```

## End-of-session update checklist

1. Mark a lab complete only after focused and full tests pass.
2. Add or update its theory page, lab guide, and senior quiz.
3. Update `docs/coverage.md` with evidence and remaining operational work.
4. Add the completed lab to the table above.
5. Change “Resume here” to the next incomplete lab and its intended artifacts.
6. Update known limitations and verification results.
7. Do not maintain a second progress list elsewhere.
