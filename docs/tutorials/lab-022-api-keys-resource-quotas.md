# LAB-022: API Keys and Resource Quotas

## Status

- Theory prerequisite: `docs/theory/api-keys-resource-quotas.md`
- Implementation: `rest-api` module
- Tests: `ApiKeysAndQuotasLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ApiKeysAndQuotasLabTest'`

## Measurable objective

Build a dedicated `/apikey/**` filter chain that authenticates callers with an `X-API-Key` header, maps the key to roles, enforces a per-key request quota, and rejects missing, invalid, or over-limit keys.

## Source artifact map

| File | Purpose |
|---|---|
| `ApiKey.java` | Record representing an API key with name, roles, quota, and window |
| `ApiKeyRepository.java` | In-memory lookup of valid keys (lab only; production should hash secrets) |
| `ApiKeyAuthenticationToken.java` | Spring `Authentication` implementation for API key callers |
| `ApiKeyRateLimiter.java` | Sliding-window per-key rate limiter |
| `ApiKeyAuthenticationFilter.java` | `OncePerRequestFilter` that extracts, validates, and rate-limits the key and sets the `SecurityContext` |
| `ApiKeyAuthConfig.java` | Isolated `SecurityFilterChain` for `/apikey/**` with `AuthorizationFilter` ordering |
| `ApiKeyController.java` | `/apikey/user` and `/apikey/admin` endpoints |
| `ApiKeysAndQuotasLabTest.java` | Positive, negative, and quota-exceeded tests |

## Exercises

1. Review `ApiKeyAuthenticationFilter` and explain why it restricts itself to `/apikey/**` via `shouldNotFilter`.
2. Trace how `ApiKeyAuthConfig` keeps the API-key chain from colliding with the other `SecurityFilterChain` beans.
3. Run `ApiKeysAndQuotasLabTest` and confirm the 11th request returns `429`.
4. List the production changes needed to move from in-memory plaintext keys to a secure key vault with hashed storage.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ApiKeysAndQuotasLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| User key on `/apikey/user` | 200, `API key user: user-key` |
| Admin key on `/apikey/admin` | 200, `API key admin: admin-key [ROLE_ADMIN]` |
| User key on `/apikey/admin` | 403 |
| Missing `X-API-Key` | 401 |
| Invalid `X-API-Key` | 401 |
| 11th request within quota window | 429 Too Many Requests |

## Production extension

- Store only a one-way hash of the key plus a non-secret prefix/identifier for lookup.
- Add a vault-backed repository with key metadata: issued-to, expiry, scopes, and last used.
- Move rate limiting to a shared cache such as Redis or a gateway to enforce limits across replicas.
- Rotate keys by issuing new ones, expiring old ones, and surfacing `X-RateLimit-Remaining` headers.
- Add audit events for key creation, revocation, and anomalous request rates.
- Never log the full key; log only the prefix when required.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ApiKeysAndQuotasLabTest'
BUILD SUCCESSFUL
ApiKeysAndQuotasLabTest: 6 passed
```

## Next lab

LAB-023 — Delegated Access and Token Exchange (or continue with the next unimplemented lab in `docs/progress.md`).
