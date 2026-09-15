# Token Lifecycle

## Security objective

Tokens expire, can be refreshed, and sometimes must be revoked. An application must use the token's natural lifetime as one security control, not treat a token as valid indefinitely.

## Tokens involved in OIDC/OAuth2

| Token | Typical lifetime | Where it lives |
|---|---|---|
| Authorization code | Seconds to minutes | URL and immediate server exchange only |
| Access token | Minutes | `Authorization` header to APIs |
| ID token | Minutes to one hour | Client session establishment |
| Refresh token | Hours to days | Secure server-side storage |

## Refresh

When an access token is about to expire, a client can exchange a refresh token for a new access token. A refresh token does not need the user's browser interaction again. For a public client, refresh tokens are high-value targets and should be bound, rotated, or stored server-side behind a BFF.

## Revocation

Two patterns exist:

- **Token-level revocation:** `POST /revoke` tells the IdP to mark a token invalid.
- **Session-level logout:** Front-channel, back-channel, or self-contained logout removes the IdP session. This invalidates all tokens issued under that session but may not remove tokens already in the client's possession.

## Handling expiry in code

- Decode `exp` and refresh proactively.
- Never ignore 401 from a resource server; inspect `WWW-Authenticate`.
- Do not keep refresh tokens in the browser for public clients.
- For server-side clients, keep refresh tokens in an encrypted store.

## Trust and failure cases

- Long-lived access tokens without revocation
- Refresh token in browser local storage or memory for an SPA
- Missing `exp` validation on an API
- Relying on logout at the client only, not the IdP
- Not handling failed refresh by forcing re-login
- Using a revoked token until a cached expiry check finally fails

Continue with [LAB-012](../tutorials/lab-012-token-lifecycle.md).
