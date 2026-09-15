# LAB-008: CORS and Security Headers

**Status:** Verified  
**Theory:** [CORS and Security Headers](../theory/cors-and-headers.md)

## Objective

Allow one configured browser origin, reject unknown origins, avoid wildcard credentialed responses, and emit hardened security headers.

## Implementation map

| Artifact | Purpose |
|---|---|
| `BrowserSecurityConfig` | Chain-scoped `CorsConfigurationSource` and headers DSL |
| `BrowserCorsHeadersLabTest` | Preflight, origin, and header assertions |

The allowed origin is `https://app.example.test`. Credentials are permitted only with that exact origin.

## Exercises

1. Send a preflight `OPTIONS /browser/profile` from the allowed origin.
2. Repeat from `https://evil.example.test` and confirm rejection.
3. Confirm the credentialed response echoes the exact origin, never `*`.
4. Inspect `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and cache directives.
5. Explain why an allowed origin is not an authenticated identity.
6. Explain why CORS does not replace the CSRF token from LAB-007.

## Verification

```bash
./gradlew :rest-api:test --tests '*BrowserCorsHeadersLabTest'
./gradlew test
```

Four assertions must pass: allowed preflight, rejected preflight, exact credentialed origin, and hardened headers.

## Attack checks

- Confirm the configuration never reflects an arbitrary request `Origin`.
- Confirm authenticated responses are not cacheable.
- Confirm framing is denied by both CSP `frame-ancestors` and `X-Frame-Options`.

## Production extension

Add HSTS on HTTPS origins, tighten CSP toward nonce-based scripts, review allowed headers and methods per route, and keep origin lists in configuration rather than code.

## Review

Complete the CORS question in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** LAB-009 Standard JWT Resource Server
