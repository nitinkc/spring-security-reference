# Project Progress and Resume Point

This is the single canonical progress record. Update it at the end of every implementation session. The Coverage Registry tracks capability maturity; this page tracks execution order and the exact resume point.

## Resume here

**Next lab:** LAB-006 — Browser Sessions and Session Fixation  
**Theory page to create:** `docs/theory/browser-sessions.md`  
**Lab guide to create:** `docs/tutorials/lab-006-browser-sessions.md`  
**Primary implementation area:** an isolated browser/session security chain that does not weaken the stateless REST chain  
**Last verified lab:** LAB-005 — Security Error Contract

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

## Remaining sequence

- **LAB-006 through LAB-009:** Browser sessions, CSRF, CORS/headers, standard JWT resource server
- **LAB-010 through LAB-020:** Local IdP, OAuth2/OIDC, OIDC SSO, SAML SSO
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

- The custom JWT utility uses a process-local symmetric key and an older JJWT API; LAB-009 replaces the recommended path with Spring Resource Server.
- OAuth2/OIDC and SAML modules are not yet runnable.
- Browser session and CSRF behavior are not yet verified.
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
