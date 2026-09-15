# Project Progress and Resume Point

This is the single canonical progress record. Update it at the end of every implementation session. The Coverage Registry tracks capability maturity; this page tracks execution order and the exact resume point.

## Resume here

- **Immediate action:** start Docker and run the following to move infrastructure-dependent labs from Implemented/Unit-Tested to Verified:
  ```bash
  docker compose -f infrastructure/idp/docker-compose.yml up -d
  ./gradlew :rest-api:test --tests '*LocalIdentityProviderLabTest'
  ./gradlew :rest-api:test --tests '*TokenLifecycleLabTest'
  ./gradlew :oauth2-auth:test
  # then start :oauth2-auth boot app on 8080 for the end-to-end browser flow
  ```
- **Next lab:** LAB-017 — SAML Relying Party
- **Theory page to create:** `docs/theory/saml-relying-party.md`
- **Lab guide to create:** `docs/tutorials/lab-017-saml-relying-party.md`
- **Primary implementation area:** a `saml-auth` module with `spring-security-saml2-service-provider`, local metadata, and a test harness for signed/unsigned responses
- **Last verified lab:** LAB-016 — API Gateway

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

## Remaining sequence

- **LAB-017 through LAB-020:** SAML, OIDC SSO, token exchange, and BFF
- **LAB-021 through LAB-028:** Service identity, delegation, BFF, mTLS, API keys, tenancy, resilience
- **LAB-029 through LAB-035:** GraphQL, gRPC, WebSocket, asynchronous messaging
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

Run with Java 21:

```bash
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
