# LAB-006: Browser Sessions and Session Fixation

**Status:** Verified  
**Theory:** [Browser Sessions and Session Fixation](../theory/browser-sessions.md)

## Objective

Prove that a browser chain creates an authenticated session, rotates the session identifier at login, and invalidates it at logout without changing the stateless REST chain.

## Implementation map

| Artifact | Purpose |
|---|---|
| `BrowserSecurityConfig` | Ordered browser chain matching `/browser/**`, `/login`, `/logout` |
| `BrowserLabController` | Public, profile, and admin browser endpoints |
| `BrowserSessionLabTest` | Session lifecycle and fixation proof |

The browser chain has its own `AuthenticationManager` with in-memory demo users (`browseruser`, `browseradmin`), so it never alters REST authentication.

## Exercises

1. Compare `SessionCreationPolicy.IF_REQUIRED` here with `STATELESS` in `MultiAuthSecurityConfig`.
2. Request `/browser/profile` anonymously and observe the redirect to login.
3. Log in with valid credentials and confirm an authenticated session.
4. Capture the pre-authentication session identifier, log in with that session, and compare identifiers.
5. Log out and assert the server session is invalid.
6. Confirm `/browser/admin/**` still enforces ADMIN.

## Verification

```bash
./gradlew :rest-api:test --tests '*BrowserSessionLabTest'
./gradlew test
```

Seven assertions must pass: public access, anonymous redirect, successful login, failed login, identifier rotation, logout invalidation, and role enforcement.

## Attack checks

- Reuse the pre-authentication identifier after login and confirm it is no longer the session.
- Confirm logout invalidates server state rather than only deleting the cookie.
- Confirm the stateless REST chain still returns JSON 401 rather than a redirect.

## Production extension

Add `Secure`, `SameSite`, idle and absolute timeouts, concurrent-session limits, and re-authentication on privilege change. Use Spring Session when sessions must survive restarts or scale horizontally.

## Review

Complete the session questions in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** [LAB-007 CSRF](lab-007-csrf.md)
