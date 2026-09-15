# JWT Resource Server

## Security objective

An API accepts a bearer token issued by a trusted authorization server and authorizes the request from verified claims. The API validates the token; it does not issue it and does not hold the signing key.

## What a JWT proves

A verified JWT proves that a party holding the signing key asserted these claims before expiry. It does not prove the caller is the legitimate holder unless the token is sender-constrained, and it does not prove the token was intended for this API unless the audience is validated.

## Required validation

| Claim/element | Why it matters |
|---|---|
| Signature and `alg` | Integrity; reject unexpected algorithms and `none` |
| `kid` | Selects trusted verification key |
| `iss` | Token came from the expected issuer |
| `aud` | Token was intended for this API |
| `exp`, `nbf`, `iat` | Time window with bounded clock skew |
| `sub` | Subject identity |
| Scopes/roles | Authorization input, mapped through an allow list |

The trusted issuer and key source must come from server configuration. A token must never select its own verification endpoint, which would enable SSRF and trust confusion.

## Spring Security model

| Responsibility | Spring API |
|---|---|
| Enable bearer authentication | `oauth2ResourceServer().jwt(...)` |
| Decode and verify | `JwtDecoder`, `NimbusJwtDecoder` |
| Claim validation | `OAuth2TokenValidator<Jwt>`, `JwtTimestampValidator`, `JwtIssuerValidator`, `JwtClaimValidator` |
| Claims to authorities | `JwtAuthenticationConverter`, `JwtGrantedAuthoritiesConverter` |
| Authenticated principal | `Jwt` in the `SecurityContext` |
| Missing/invalid token response | `BearerTokenAuthenticationEntryPoint` (401) |
| Insufficient authority response | Access denied handling (403) |

Spring maps a `scope`/`scp` claim to `SCOPE_` authorities by default. A custom claim such as `roles` needs an explicit converter and prefix.

## Why this replaces a custom bearer filter

A hand-written filter typically misses algorithm restriction, issuer and audience checks, key rotation, clock skew, and consistent error semantics. A process-local symmetric key also breaks horizontal scaling and lets every verifier mint tokens.

## Trust and failure cases

- Accepting any issuer or fetching keys from a token-supplied URL
- Skipping audience validation, enabling token reuse across APIs
- Accepting unexpected algorithms or unsigned tokens
- Trusting a self-asserted `roles` claim without an allow list
- No key-rotation or unknown-`kid` behavior
- Logging full tokens during troubleshooting

## Transfer

Python and Node JOSE libraries require the same explicit checks, usually with more manual wiring. `JwtDecoder`, validator composition, and converter-based authority mapping are Spring-specific.

Continue with [LAB-009](../tutorials/lab-009-jwt-resource-server.md).
