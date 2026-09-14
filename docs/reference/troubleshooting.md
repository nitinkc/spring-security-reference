# Troubleshooting

## 401 Unauthorized

Confirm that credentials reached the application, the expected filter owns the request, the token or session is valid, and authentication was stored in the `SecurityContext`. For JWTs, inspect issuer, audience, signature algorithm, expiry, not-before, and clock skew without logging the token.

## 403 Forbidden

Authentication succeeded but authorization failed. Compare normalized authorities with the request and method rules. Remember that `hasRole("ADMIN")` checks for `ROLE_ADMIN`.

## Unexpected public access

Check matcher order, overlapping filter chains, profile activation, dispatcher types, management endpoints, and whether method security is enabled. Add a negative integration test before changing rules.

## CSRF failures

Determine whether the request uses browser cookies or a bearer token. Cookie-authenticated state changes should include a valid CSRF token. Do not disable CSRF globally to hide a broken browser flow.

## OAuth2/OIDC failures

Verify redirect URI equality, state, nonce, PKCE, client type, issuer discovery, system time, and provider session state. Keep client credentials out of diagnostics.

## SAML failures

Verify entity IDs, ACS URL, metadata, trusted signing certificate, audience, recipient, assertion timing, request correlation, and attribute names. LAB-019 provides the negative-test matrix.

## Build checks

```bash
./gradlew test
uv run --with-requirements requirements.txt mkdocs build --strict
```

See the [Authentication Testing Reference](testing-auth.md), [Custom Providers Reference](custom-providers.md), and [Advanced Patterns Reference](advanced-patterns.md).
