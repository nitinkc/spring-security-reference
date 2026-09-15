# LAB-009: Standard JWT Resource Server

**Status:** Verified with a locally generated RSA key pair  
**Theory:** [JWT Resource Server](../theory/jwt-resource-server.md)

## Objective

Protect an API path with Spring Security's resource-server support and prove that signature, issuer, audience, expiry, and authority checks all reject invalid tokens.

## Implementation map

| Artifact | Purpose |
|---|---|
| `JwkLabKeyProvider` | Generates current and previous lab RSA keys for rotation demonstrations |
| `ResourceServerSecurityConfig` | `/rs/**` chain, `JwtDecoder` built from an in-process `JWKSource`, validators, authority converter |
| `ResourceServerLabController` | `/rs/profile` and `/rs/admin/report` |
| `ResourceServerJwtLabTest` | Nine positive and negative token scenarios |

Configuration values:

- Issuer: `https://issuer.example.test`
- Audience: `spring-security-reference-api`
- Authorities: `roles` claim with a `ROLE_` prefix

## Exercises

1. Issue a valid RS256 token and call `/rs/profile`.
2. Call without a token and inspect the 401 and `WWW-Authenticate` header.
3. Send a malformed token value.
4. Issue an expired token.
5. Change the issuer, then the audience.
6. Sign with a different RSA key while keeping the same `kid`.
7. Call `/rs/admin/report` with `USER`, then with `ADMIN`.
8. Compare this chain with the custom JWT filter in `common-auth`.

## Verification

```bash
./gradlew :rest-api:test --tests '*ResourceServerJwtLabTest'
./gradlew test
```

Expected results:

| Scenario | Result |
|---|---|
| Valid token | 200 |
| No token | 401 |
| Malformed token | 401 |
| Expired token | 401 |
| Wrong issuer | 401 |
| Wrong audience | 401 |
| Untrusted signing key | 401 |
| `USER` on admin route | 403 |
| `ADMIN` on admin route | 200 |

## Attack checks

- Confirm a matching `kid` does not bypass signature verification.
- Confirm an attacker-supplied `roles` claim cannot grant ADMIN once the converter uses an allow-listed claim from a trusted issuer.
- Confirm no token material appears in logs or responses.

## Production extension

Replace the local key pair with `issuer-uri` discovery or a configured JWK set URL, add key rotation and unknown-`kid` behavior, restrict algorithms, add clock-skew policy, and define JWK-endpoint outage behavior. The custom JWT filter should be treated as educational only.

## Review

Complete the token-validation questions in the [SSO and Federation Quiz](../quizzes/federation.md).

**Next:** [LAB-010 Local Identity Provider](lab-010-local-identity-provider.md)
