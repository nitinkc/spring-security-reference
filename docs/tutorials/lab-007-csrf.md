# LAB-007: CSRF Protection

**Status:** Verified  
**Theory:** [Cross-Site Request Forgery](../theory/csrf.md)

## Objective

Prove that cookie-authenticated state changes require a valid CSRF token and that missing, invalid, and cross-site submissions fail.

## Implementation map

| Artifact | Purpose |
|---|---|
| `BrowserSecurityConfig` | Keeps Spring's default CSRF protection enabled for the browser chain |
| `BrowserLabController.updateProfile` | State-changing `POST /browser/profile` |
| `BrowserCsrfLabTest` | Positive and negative token proof |

The stateless REST chain still disables CSRF because it authenticates with an explicit bearer header rather than ambient cookies. LAB-009 revisits that decision with the standard resource server.

## Exercises

1. Submit `POST /browser/profile` with a valid token and confirm success.
2. Remove the token and confirm HTTP 403.
3. Submit an invalid token and confirm HTTP 403.
4. Add a foreign `Origin` header without a token and confirm rejection.
5. Confirm `GET /browser/profile` needs no token.
6. Explain why disabling CSRF globally would break the browser chain's guarantees.

## Verification

```bash
./gradlew :rest-api:test --tests '*BrowserCsrfLabTest'
./gradlew test
```

Four assertions must pass: valid token, missing token, invalid token, and cross-site submission.

## Attack checks

- Confirm the token is not accepted from a URL query parameter by default.
- Confirm no CSRF token appears in logs or error responses.
- Confirm login and logout are protected rather than exempted.

## Production extension

For an SPA or BFF, use `CookieCsrfTokenRepository.withHttpOnlyFalse()` with a matching request handler, rotate the token with the session, and exempt only narrowly documented endpoints.

## Review

Complete the CSRF question in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** [LAB-008 CORS and Headers](lab-008-cors-and-headers.md)
