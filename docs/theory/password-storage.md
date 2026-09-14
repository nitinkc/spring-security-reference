# Password Storage and Migration

## Security objective

Store a slow, salted, one-way password hash. Preserve enough format metadata to verify older records and migrate them after successful authentication.

Passwords should not be encrypted for later recovery. Encryption preserves reversibility and creates a decryption-key compromise path.

## Spring Security model

`DelegatingPasswordEncoder` stores values as `{id}encodedPassword`. The identifier selects an encoder without silently treating malformed or unprefixed values as plaintext.

| Responsibility | Spring API |
|---|---|
| Create recommended delegating encoder | `PasswordEncoderFactories.createDelegatingPasswordEncoder()` |
| Verify password | `PasswordEncoder.matches` |
| Detect upgrade need | `PasswordEncoder.upgradeEncoding` |
| Current repository default | `{bcrypt}` |

## Migration sequence

1. Read the versioned stored value.
2. Verify the submitted password with the selected old encoder.
3. Only after success, encode the submitted password with the current encoder.
4. Replace the stored hash atomically.
5. Handle concurrent successful logins without corrupting credentials.
6. Audit migration without recording passwords or hashes.

Unknown users should perform bounded dummy-hash work before generic failure. Work factors must balance offline-attack resistance, login latency, and denial-of-service exposure.

## Trust and failure cases

- Plaintext or reversible storage
- Unprefixed fallback to plaintext
- Migration after a failed match
- Fast unsalted hashes
- Hashes or passwords in logs
- Work factor never reviewed as hardware changes

## Transfer

Python Argon2/bcrypt and Node argon2/bcrypt libraries use the same verify-then-upgrade pattern. Spring's delegating `{id}` format and `upgradeEncoding` method are framework-specific.

Continue with [LAB-003](../tutorials/lab-003-password-storage.md).
