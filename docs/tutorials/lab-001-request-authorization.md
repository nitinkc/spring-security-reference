# LAB-001: Request Authorization

**Status:** Verified  
**Theory:** [Request Authorization and Filter Chains](../theory/request-authorization.md)

## Objective

Prove public, authenticated, role-restricted, and denied requests against the production `MultiAuthSecurityConfig`.

## Prerequisites

- Java 21
- Read the linked theory page
- Understand `ROLE_USER` and `ROLE_ADMIN`

## Implementation map

| Artifact | Purpose |
|---|---|
| `MultiAuthSecurityConfig` | Production request rules and filter chain |
| `ApiController` | Public, USER, and ADMIN endpoints |
| `RequestAuthorizationLabTest` | MockMvc proof against production configuration |

## Exercises

1. Inspect the order of `/api/public/**`, `/api/admin/**`, and `/api/user/**` matchers.
2. Run the focused test.
3. Trace the selected chain and resulting `SecurityContext` in debug output.
4. Add a temporary broad matcher in the wrong position and confirm a negative test detects the exposure; revert it.
5. Verify USER cannot invoke the ADMIN endpoint.

## Verification

```bash
./gradlew :rest-api:test --tests '*RequestAuthorizationLabTest'
./gradlew test
```

Expected matrix:

| Request | Identity | Result |
|---|---|---|
| `/api/public/hello` | Anonymous | 200 |
| `/api/user/secure` | Anonymous | 401 |
| `/api/user/secure` | USER | 200 |
| `/api/admin/secure` | USER | 403 |
| `/api/admin/secure` | ADMIN | 200 |

## Completion evidence

The tests import the production chain, use the real JWT filter with mocked JWT cryptography, and mock only the custom credential provider. Coverage may remain Verified while these tests pass.

## Review

Complete the filter-chain and 401/403 questions in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** [LAB-002 Secure Login](lab-002-secure-login.md)
