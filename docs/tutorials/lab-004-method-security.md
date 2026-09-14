# LAB-004: Method Security

**Status:** Verified  
**Theory:** [Method Security](../theory/method-security.md)

## Objective

Protect service methods independently of HTTP routes and prove ADMIN-only and owner-or-ADMIN decisions through the Spring-managed proxy.

## Implementation map

| Artifact | Purpose |
|---|---|
| `MethodSecurityConfig` | Enables Spring method interception |
| `AuthorizationService.adminOperation` | ADMIN-only operation |
| `AuthorizationService.readProfile` | Owner-or-ADMIN operation |
| `AuthorizationServiceMethodSecurityLabTest` | Direct proxy invocation tests |
| Root `build.gradle` | Retains parameter names with `-parameters` |

## Exercises

1. Invoke the injected service anonymously and observe the authentication failure.
2. Invoke the ADMIN operation as USER and ADMIN.
3. Read the matching and non-matching profile as USER.
4. Read another profile as ADMIN.
5. Explain why constructing `new AuthorizationService()` would invalidate the test.
6. Sketch a self-invocation bypass and refactor the protected method to a separate bean boundary.

## Verification

```bash
./gradlew :authorization-service:test --tests '*AuthorizationServiceMethodSecurityLabTest'
./gradlew test
```

Six tests must prove anonymous denial, role denial, ADMIN access, owner access, cross-user denial, and ADMIN override.

## Production extension

Replace demonstration usernames with domain-backed immutable resource ownership. Move complex policy from SpEL into a tested `AuthorizationManager` or policy service.

## Review

Complete the method-security self-invocation question in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** [LAB-005 Security Errors](lab-005-security-errors.md)
