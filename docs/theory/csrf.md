# Cross-Site Request Forgery

## Security objective

Prevent another site from causing an authenticated browser to perform a state-changing request. CSRF exploits ambient credentials, not stolen ones.

A request is vulnerable when the browser attaches credentials automatically: session cookies, Basic credentials, or client certificates. Requests authenticated by an explicit `Authorization: Bearer` header supplied by application code are not automatically attached by the browser.

## Why common assumptions fail

- **"It is a JSON API."** Response format does not stop a forged request.
- **"The cookie is HttpOnly."** The browser still sends it.
- **"CORS protects us."** CORS restricts reading responses and triggers preflight only for non-simple requests; it is not a general CSRF defense.
- **"We only use POST."** Forged POSTs are trivial to issue.

## Spring Security model

| Responsibility | Spring API |
|---|---|
| Enable protection | `csrf()` (default on for stateful chains) |
| Token storage | `CsrfTokenRepository`, `CookieCsrfTokenRepository` |
| SPA cookie handling | `CookieCsrfTokenRepository.withHttpOnlyFalse()` |
| Token resolution | `CsrfTokenRequestHandler` |
| Selective exemption | `csrf().ignoringRequestMatchers(...)` |
| Test token | `SecurityMockMvcRequestPostProcessors.csrf()` |

Spring ignores safe methods such as GET and HEAD and enforces the token on state-changing methods.

## Decision guide

| Authentication style | CSRF requirement |
|---|---|
| Cookie session, server-rendered | Synchronizer token required |
| Cookie session, SPA/BFF | Token required, readable by the SPA |
| Bearer token in a header from application code | Generally not required |
| Basic auth in a browser | Required |

Disabling CSRF globally to fix a broken browser flow is a security regression. Exempt narrowly and document why.

## Trust and failure cases

- Global disable applied to cookie-authenticated endpoints
- State-changing GET endpoints
- Token exposed in URLs or logs
- Login and logout excluded from protection
- Token not rotated with the session

## Transfer

Every framework must bind a state-changing request to proof of same-site origin. Spring's repository and request-handler abstractions are framework-specific.

Continue with [LAB-007](../tutorials/lab-007-csrf.md).
