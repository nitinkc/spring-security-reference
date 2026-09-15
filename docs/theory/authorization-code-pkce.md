# Authorization Code with PKCE

## Security objective

A browser obtains an access token without exposing a client secret to client-side code and without leaking the authorization code to a malicious application. Proof Key for Code Exchange (PKCE) was originally for public mobile clients and is now recommended for all browser-based clients.

## Flow

```text
Client          Browser          IdP
  |                |              |
  |  ← generate state, nonce, code_verifier  |
  |                |              |
  |                |  GET /auth?client_id=..., redirect_uri=..., scope=..., state=..., nonce=..., code_challenge=...  |
  |                |              |
  |                |  redirect 302 to login / consent |
  |                |              |
  |                |  POST login + consent |
  |                |              |
  |                |  302 redirect to redirect_uri?code=...&state=...  |
  |                |              |
  |  compare state |              |
  |                |  POST /token code, code_verifier, client_id, redirect_uri |
  |                |              |
  |                |  access_token, id_token, refresh_token |
  |                |              |
  | validate id_token (iss, aud, exp, nonce) |
```

The `state` parameter prevents CSRF on the callback. The `nonce` prevents token replay for ID tokens. The `code_verifier` prevents a malicious application that intercepted the code from exchanging it.

## Public versus confidential clients

| Client type | Has secret? | Uses PKCE? |
|---|---|---|
| Public (SPA, mobile) | No | Required |
| Confidential (server-side web app) | Yes | Recommended |

## Spring Security model

| Responsibility | Spring API |
|---|---|
| Client registration | `ClientRegistration` with `AuthorizationGrantType.AUTHORIZATION_CODE` and PKCE proof key |
| Discovery bypass | Hard-coded authorization/token/JWK URIs against a known issuer |
| Authorization resolver | `DefaultOAuth2AuthorizationRequestResolver` with `OAuth2AuthorizationRequestCustomizers.withPkce()` |
| Token endpoint | `DefaultAuthorizationCodeTokenResponseClient` |
| ID token validation | `OidcAuthorizationCodeAuthenticationProvider` |
| User mapping | `OidcUserService` |
| Login filter chain | `oauth2Login()` |

## Trust and failure cases

- Missing `state` comparison on callback
- Missing `nonce` validation on ID token
- Wildcard `redirect_uri` registered with the IdP
- Client secret shipped to the browser
- Accepting an issuer not from server configuration
- Not validating token `audience` for the API
- Refresh token in browser local storage
- Missing end-session / back-channel logout path

## Transfer

The Authorization Code + PKCE flow is protocol. The registration format, resolver, and success handler are Spring-specific.

Continue with [LAB-011](../tutorials/lab-011-authorization-code-pkce.md).
