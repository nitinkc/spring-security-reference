# LAB-005: Security Error Contract

**Status:** Verified for the stateless REST chain  
**Theory:** [Security Error Boundaries](../theory/security-errors.md)

## Objective

Return stable JSON for missing authentication and insufficient authority without exposing exceptions, policies, authorities, tokens, or stack traces.

## Implementation map

| Artifact | Purpose |
|---|---|
| `SecurityErrorResponse` | Stable response schema |
| `JsonAuthenticationEntryPoint` | HTTP 401 serialization |
| `JsonAccessDeniedHandler` | HTTP 403 serialization |
| `MultiAuthSecurityConfig` | Production handler registration |
| `RequestAuthorizationLabTest` | Exact contract and non-disclosure assertions |

## Exercises

1. Request `/api/user/secure` anonymously and inspect the entry-point response.
2. Request `/api/admin/secure` as USER and inspect the denied-handler response.
3. Confirm JSON content type and stable machine codes.
4. Confirm exception, authorities, and expression fields are absent.
5. Compare filter-boundary handling with the controller login exception handler.
6. Explain why a browser login chain may redirect instead of using this JSON contract.

## Verification

```bash
./gradlew :rest-api:test --tests '*RequestAuthorizationLabTest'
./gradlew test
```

Expected machine codes:

| Status | Code |
|---|---|
| 401 | `authentication_required` |
| 403 | `access_denied` |

## Attack checks

- Ensure exception messages never become response content.
- Ensure paths cannot inject invalid JSON; serialization must use `ObjectMapper`.
- Ensure credentials and authorization details remain absent from logs and bodies.

## Review

Complete the entry-point and denied-handler questions in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** [LAB-006 Browser Sessions](lab-006-browser-sessions.md)
