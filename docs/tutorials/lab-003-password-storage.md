# LAB-003: Password Storage and Migration

**Status:** Verified  
**Theory:** [Password Storage and Migration](../theory/password-storage.md)

## Objective

Use `DelegatingPasswordEncoder`, reject unprefixed plaintext storage, and upgrade an explicitly legacy hash only after successful authentication.

## Implementation map

| Artifact | Purpose |
|---|---|
| `PasswordSecurityConfig` | Shared delegating encoder bean |
| `InMemoryCredentialRepository` | Current and legacy demonstration records |
| `AuthService` | Match, dummy-hash work, and upgrade decision |
| `AuthServicePasswordMigrationLabTest` | Encoding and migration proof |

## Exercises

1. Inspect the ADMIN `{bcrypt}` value and USER `{noop}` legacy value.
2. Authenticate ADMIN and confirm no migration is required.
3. Authenticate USER successfully and inspect the changed prefix.
4. Attempt USER with a wrong password and confirm storage does not change.
5. Store an unprefixed value and confirm authentication fails safely.

## Verification

```bash
./gradlew :common-auth:test --tests '*AuthServicePasswordMigrationLabTest'
./gradlew :rest-api:test --tests '*LoginAuthenticationLabTest'
./gradlew test
```

## Completion evidence

Tests prove current versioned storage, plaintext rejection, success-only migration, failure without migration, and compatibility with the production login flow.

## Production extension

Replace the in-memory repository with persistent atomic compare-and-update behavior. Benchmark the work factor, handle concurrent logins, and audit migration without logging passwords or hashes.

## Review

Complete the password migration questions in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** [LAB-004 Method Security](lab-004-method-security.md)
