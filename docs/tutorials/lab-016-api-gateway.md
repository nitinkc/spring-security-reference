# LAB-016: API Gateway

**Status:** Verified  
**Theory:** [API Gateway](../theory/api-gateway.md)

## Objective

Add a `gateway` module that validates a JWT bearer token, enforces scope-based route authorization, and returns the enriched headers that would be forwarded to a downstream service.

## Implementation map

| Artifact | Purpose |
|---|---|
| `gateway/build.gradle` | New module with `spring-boot-starter-web`, security, oauth2-resource-server, and the common-security library |
| `GatewayApplication` | Boot entry point |
| `GatewayConfig` | JWT resource-server chain with `SCOPE_USER` and `SCOPE_ADMIN` route rules |
| `GatewayController` | Learning routes that echo the caller, target, and forwarded headers |
| `GatewayLabTest` | Five scope, authentication, and header-forwarding tests |

## Exercises

1. Request `/gateway/user/route` with a `USER` scoped token.
2. Request `/gateway/admin/route` with a `USER` token and observe 403.
3. Request `/gateway/admin/route` with an `ADMIN` token.
4. Request without a token and observe 401.
5. Inspect the `forwarded` response block and confirm `X-User-Subject` and `X-User-Scope` are present.
6. Discuss why a real gateway must not log or return the original bearer token.
7. Document how a `WebClient` or `RestClient` proxy would route to `target` with the enriched headers.

## Verification

```bash
./gradlew :gateway:test
./gradlew test
```

Five gateway assertions must pass.

## Attack checks

- Confirm the gateway does not echo the bearer token value in the response.
- Confirm a `USER` token cannot reach the admin route.
- Confirm missing tokens produce 401, not 403.
- Confirm the `scope` claim is converted to `SCOPE_*` authorities.

## Production extension

Use Spring Cloud Gateway with `TokenRelayGatewayFilterFactory`, per-route scopes, rate limiting, TLS, and token exchange. Ensure downstream services independently validate the forwarded token or an exchanged token scoped to their audience.

## Review

Complete the gateway questions in the [SSO and Federation Quiz](../quizzes/federation.md).

**Next:** LAB-017 SAML Relying Party
