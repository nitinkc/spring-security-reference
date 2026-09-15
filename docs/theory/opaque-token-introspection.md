# Opaque Token Introspection

## Security objective

Not all access tokens are self-contained JWTs. An opaque (reference) token is a random identifier that the resource server validates by calling an introspection endpoint. This keeps token state at the authorization server and enables instant revocation.

## When to use opaque tokens

| Situation | Preference |
|---|---|
| Immediate revocation required | Opaque tokens |
| No ability to rotate signing keys quickly | Opaque tokens |
| Need to enforce token binding or short lifetimes strictly | Opaque tokens |
| Stateless validation and horizontal scaling | JWTs with short lifetimes |
| Cross-domain verification without IdP calls | JWTs with JWK discovery |

## Introspection contract

RFC 7662 defines a request to `POST /introspect` with `token=<token>` and a response:

```json
{
  "active": true,
  "sub": "alice",
  "client_id": "api-client",
  "exp": 1700000000,
  "scope": "read write"
}
```

`active=false` is returned for invalid, expired, or revoked tokens. A 200 with `{"active": false}` is correct; 401 means the caller could not authenticate to the introspection endpoint.

## Spring Security model

| Responsibility | Spring API |
|---|---|
| Enable opaque resource server | `oauth2ResourceServer().opaqueToken()` |
| Introspector | `OpaqueTokenIntrospector`, `NimbusOpaqueTokenIntrospector` |
| Authentication | `BearerTokenAuthentication` with `OAuth2AuthenticatedPrincipal` |
| Scope to authority | `SCOPE_` prefix on the `scope` claim |
| Principal name | `sub` claim |
| Attributes | Additional claims returned by the introspection endpoint |

## Trust and failure cases

- Storing the access token in the resource server
- Trusting a token because it is well-formed rather than because the IdP says `active`
- Skipping the `exp` check
- Calling introspection over HTTP in production
- Not authenticating the resource server to the introspection endpoint
- Returning verbose claims for inactive tokens
- Caching introspection results too long, defeating instant revocation

Continue with [LAB-013](../tutorials/lab-013-opaque-token-introspection.md).
