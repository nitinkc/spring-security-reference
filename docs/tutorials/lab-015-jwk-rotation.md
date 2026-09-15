# LAB-015: JWK Rotation and Multiple Issuers

**Status:** Verified  
**Theory:** [JWK Rotation and Multiple Issuers](../theory/jwk-rotation.md)

## Objective

Prove that the resource server accepts tokens signed by either the current or the previous key, rejects unknown `kid`s, and validates issuer and audience independently of the JWK source.

## Implementation map

| Artifact | Purpose |
|---|---|
| `JwkLabKeyProvider` | Generates two RSA keys with `current` and `previous` identifiers |
| `ResourceServerSecurityConfig` | `NimbusJwtDecoder` built with `JWSVerificationKeySelector` over a `JWKSource` containing both keys |
| `ResourceServerJwtLabTest` | Eleven JWT scenarios including rotation, unknown `kid`, and untrusted key |

## Exercises

1. Issue a token signed with the current key and access `/rs/profile`.
2. Issue a token signed with the previous key and confirm it is still accepted.
3. Issue a token with an unknown `kid` and confirm 401.
4. Sign a token with a fresh attacker key using the same `kid` and confirm 401.
5. Change the issuer and confirm 401.
6. Change the audience and confirm 401.
7. Explain why `kid` alone does not prove a token is valid.
8. Document how a real `issuer-uri` and `jwkSetUri` would replace the in-process JWK source.

## Verification

```bash
./gradlew :rest-api:test --tests '*ResourceServerJwtLabTest'
./gradlew test
```

Eleven assertions must pass, including the new rotation and unknown-`kid` cases.

## Attack checks

- Confirm the `kid` is only a key-selection hint, not an authority.
- Confirm a matching `kid` from an untrusted key does not bypass verification.
- Confirm `alg=none` or unexpected `alg` values are rejected.
- Confirm the JWK source is from server configuration, not the token.

## Production extension

Use `spring.security.oauth2.resourceserver.jwt.issuer-uri` with JWK discovery, implement a bounded JWK cache, and add a rotation runbook with an overlap window and emergency-replacement procedure.

## Review

Complete the JWK and issuer questions in the [SSO and Federation Quiz](../quizzes/federation.md).

**Next:** LAB-016 API Gateway
