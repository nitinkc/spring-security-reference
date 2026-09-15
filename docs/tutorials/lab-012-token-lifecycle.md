# LAB-012: Token Lifecycle

**Status:** Implemented (opt-in, not yet executed)  
**Theory:** [Token Lifecycle](../theory/token-lifecycle.md)

## Objective

Demonstrate token expiry, refresh, and revocation against the local IdP once it is running.

## Planned implementation

1. Add a `TokenLifecycleLabTest` to the `rest-api` or `oauth2-auth` module that requires the IdP and verifies:
   - Access token has a bounded `exp`.
   - Refresh token can be used to obtain a new access token with a different `jti` and `exp`.
   - Old access token is rejected after `exp`.
   - Revocation of the refresh token prevents issuing new access tokens.
2. Document `expires_in`, `refresh_expires_in`, and how a BFF or server-side client should store and rotate refresh tokens.
3. Add sample `/logout` handling that removes the client session and triggers front-channel end-session.

## Verification

```bash
./gradlew :rest-api:test --tests '*TokenLifecycleLabTest'
```

This will self-skip without Docker.

## Attack checks

- Confirm the access token cannot be used after `exp`.
- Confirm revoked refresh tokens cannot mint new access tokens.
- Confirm logout removes the IdP session.

## Production extension

Use sender-constrained tokens via DPoP or mTLS, keep refresh tokens in a secure server-side store, implement back-channel logout, and handle `invalid_grant` by forcing re-authentication.

**Next:** LAB-013 OAuth2/OIDC Token Security
