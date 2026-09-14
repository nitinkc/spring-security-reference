# LAB-002: Secure Username/Password Login

**Status:** Verified  
**Theory:** [Authentication Managers and Providers](../theory/authentication-providers.md)

## Objective

Authenticate through Spring's `AuthenticationManager` before issuing a JWT and return one public failure contract for unknown users and wrong passwords.

## Implementation map

| Artifact | Purpose |
|---|---|
| `ApiController.login` | Creates an unauthenticated token and consumes the authenticated result |
| `AuthenticationManager` | Selects a supporting provider |
| `CustomAuthenticationProvider` | Validates credentials and creates trusted authorities |
| `AuthService` | Reads and verifies the credential record |
| `LoginAuthenticationLabTest` | Production-flow integration proof |

## Exercises

1. Trace the submitted username/password into `UsernamePasswordAuthenticationToken.unauthenticated`.
2. Follow provider selection through `AuthenticationManager`.
3. Confirm the JWT subject and role come from returned `Authentication`.
4. Submit a wrong password and unknown username; compare status and body.
5. Verify failed authentication never calls token generation.

## Verification

```bash
./gradlew :rest-api:test --tests '*LoginAuthenticationLabTest'
./gradlew test
```

Expected behavior:

- Valid `admin/password` returns a token with `ROLE_ADMIN`.
- Wrong password returns HTTP 401 and `invalid_credentials`.
- Unknown user returns the same public response.
- Authenticated credentials are erased.

## Attack checks

- Add a role request parameter and prove it has no effect.
- Verify arbitrary usernames cannot mint tokens.
- Search logs and responses for raw passwords and reusable token diagnostics.

## Review

Complete the authentication-provider and token-issuance questions in the [Spring Security Internals Quiz](../quizzes/fundamentals.md).

**Next:** [LAB-003 Password Storage](lab-003-password-storage.md)
