# LAB-026: API Key Lifecycle

## Status

- Theory prerequisite: `docs/theory/api-key-lifecycle.md`
- Implementation: `rest-api` module
- Tests: `ApiKeyLifecycleLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ApiKeyLifecycleLabTest'`

## Measurable objective

Replace the plaintext API-key store from LAB-022 with a lifecycle-aware implementation: issue prefixed keys, store only salted hashes, enforce scopes, support rotation with a bounded grace period, and support immediate revocation. Tests must prove active, expired, revoked, wrong-scope, and rotated keys behave correctly, and that a stored hash cannot be used as a credential.

## Source artifact map

| File | Purpose |
|---|---|
| `SecureApiKey.java` | Key metadata record with salt, hash, scopes, and lifecycle timestamps |
| `SecureApiKeyService.java` | Issue, rotate, revoke, and validate keys with salted SHA-256 storage |
| `SecureApiKeyAuthenticationToken.java` | `Authentication` implementation for API-key callers |
| `SecureApiKeyAuthenticationFilter.java` | `OncePerRequestFilter` for the lifecycle chain, bound to the data endpoints only |
| `SecureApiKeyLifecycleConfig.java` | `SecurityFilterChain` for `/apikey-life/**` with `SCOPE_USER` and `SCOPE_ADMIN` rules |
| `SecureApiKeyLifecycleController.java` | `/apikey-life/issue`, `/apikey-life/revoke`, `/apikey-life/rotate`, and data endpoints |
| `ApiKeyLifecycleLabTest.java` | Active, scope, expiry, revocation, tampering, and rotation-with-grace tests |

## Exercises

1. Review `SecureApiKeyService` and explain why the salt must be stored alongside the hash but the full secret must not.
2. Trace how `issue()` returns the full key exactly once and what can be recovered from the stored record alone.
3. Run `ApiKeyLifecycleLabTest` and confirm that a revoked key is rejected immediately, while a rotated key is rejected only after its grace period expires.
4. Identify why `scope` is mapped to `SCOPE_` authorities rather than `ROLE_` authorities in this chain.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ApiKeyLifecycleLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| Active user key on `/apikey-life/user` | 200, `secure-api-key user` |
| Active admin key on `/apikey-life/admin` | 200, `secure-api-key admin` |
| User key on `/apikey-life/admin` | 403 |
| Expired key on `/apikey-life/user` | 401 |
| Revoked key on `/apikey-life/user` | 401 |
| Unknown or tampered key | 401 |
| Rotated key during grace period | 200 |
| Rotated key after grace period | 401 |

## Production extension

- Encrypt the key metadata and hashes at rest.
- Add immutable audit events for issue, rotation, and revocation.
- Use a more expensive hash such as bcrypt, Argon2, or a slow HMAC with a hardware-backed key for high-sensitivity keys.
- Move to a real database with unique prefix indexes and soft-delete retention.
- Add scopes to include resource and action granularity, not just broad access levels.
- Add rate limiting per prefix and alert on anomalous use or revocation spikes.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ApiKeyLifecycleLabTest'
BUILD SUCCESSFUL
ApiKeyLifecycleLabTest: 7 passed
```

## Next lab

LAB-027 — Tenant and Object Authorization.
