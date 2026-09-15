# LAB-013: Opaque Token Introspection

**Status:** Verified  
**Theory:** [Opaque Token Introspection](../theory/opaque-token-introspection.md)

## Objective

Demonstrate a resource server that validates bearer tokens by introspection rather than by decoding a JWT, including active, expired, missing, revoked, and scope-based cases.

## Implementation map

| Artifact | Purpose |
|---|---|
| `InMemoryOpaqueTokenRepository` | Learning store for opaque reference tokens with expiry and scope |
| `LocalOpaqueTokenIntrospector` | In-process `OpaqueTokenIntrospector` returning `OAuth2AuthenticatedPrincipal` |
| `OpaqueTokenResourceServerConfig` | `/op/**` chain using `oauth2ResourceServer().opaqueToken().introspector(...)` |
| `OpaqueTokenController` | Lab issue/revoke/introspect endpoints |
| `OpaqueResourceController` | Protected `/op/resource` and `/op/admin/resource` |
| `OpaqueTokenIntrospectionLabTest` | Nine positive and negative scenarios |

## Exercises

1. Issue a token with `USER` scope and access `/op/resource`.
2. Access `/op/admin/resource` with the `USER` token and observe 403.
3. Issue an `ADMIN` token and access the admin resource.
4. Send a request with no token and observe 401.
5. Send an unknown token and observe 401.
6. Issue a token, wait / force expiry by backdating, and observe 401.
7. Revoke a token and confirm subsequent calls return 401.
8. Call `/op/introspect` for an active and an unknown token and compare responses.
9. Explain why `SCOPE_` is the default authority prefix for opaque tokens.

## Verification

```bash
./gradlew :rest-api:test --tests '*OpaqueToken*LabTest'
./gradlew test
```

All nine scenarios pass in-process without Docker.

## Attack checks

- Confirm a well-formed random string that is not in the repository is rejected.
- Confirm a token with the right shape but past expiry is rejected.
- Confirm revocation is immediate, not bound to a TTL.
- Confirm the introspection endpoint does not leak internal attributes for inactive tokens.

## Production extension

Use `NimbusOpaqueTokenIntrospector` against a real IdP, authenticate the resource server with client credentials, call over TLS, and implement a bounded cache with eager invalidation on revocation.

## Review

Complete the token introspection questions in the [SSO and Federation Quiz](../quizzes/federation.md).

**Next:** LAB-014 Service-to-Service and Client Credentials
