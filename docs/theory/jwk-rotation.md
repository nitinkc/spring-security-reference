# JWK Rotation and Multiple Issuers

## Security objective

Signing keys should be rotated on a schedule and during incidents. A resource server must be able to verify tokens signed by the current key and, during an overlap window, tokens signed by the previous key, while rejecting unknown or untrusted keys and issuers.

## Key rotation timeline

```text
Time  ──────────────────────────────────────────────>
      [---- key A active ----]
                           [---- overlap ----]
                                                   [---- key B active ----]
```

During overlap, tokens signed by either key A or key B are valid. After key A is retired, only key B is accepted.

## Why a token must not choose its own key

A JWT header contains `alg` and `kid`. These are unauthenticated hints. If the resource server fetches JWKs from a URL supplied by the token, an attacker can point the server at their own keys and validate their own forgeries. The trusted issuer and JWK source must come from server configuration.

## Spring Security model

| Responsibility | Spring API |
|---|---|
| JWK source | `ImmutableJWKSet` or `JWKSource<SecurityContext>` |
| Key selection | `JWSVerificationKeySelector` with `JWSAlgorithm.RS256` |
| JWT processor | `DefaultJWTProcessor` |
| Decoder | `NimbusJwtDecoder` constructor with a processor |
| Issuer validation | `JwtIssuerValidator` |
| Audience validation | `JwtClaimValidator` on `aud` |

## Multiple issuers and multi-tenancy

For multiple issuers, configure a `JwtDecoder` per issuer or a tenant-aware resolver. Each tenant maps to a trusted `issuer-uri` and JWK set. Do not allow a token-supplied issuer to select the JWK source.

## Trust and failure cases

- Single fixed `withPublicKey` that cannot handle rotation
- Accepting `alg=none` or unexpected algorithms
- Trusting a `kid` match without signature verification
- Fetching JWKs from a token-controlled URL
- Missing `iss` and `aud` validation
- Not testing the overlap window between old and new keys
- Stale JWK cache after emergency rotation

## Transfer

JWS and JWK are standards; the processor, source, and validator assembly are Spring-specific.

Continue with [LAB-015](../tutorials/lab-015-jwk-rotation.md).
