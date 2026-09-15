# Backend-for-Frontend (BFF) Token Handling

A Backend-for-Frontend (BFF) keeps access tokens on the server and exposes only a session cookie to the browser. This removes bearer tokens from the browser JavaScript and reduces the attack surface for XSS, token exfiltration, and malicious third-party scripts.

## Security objective

Prevent access tokens from being held or used directly by browser-side code, while still allowing a browser application to invoke downstream APIs through a trusted server-side component.

## Core concepts

| Term | Meaning |
|---|---|
| **BFF** | A dedicated backend that serves a specific frontend and owns the token lifecycle. |
| **Session cookie** | A short-lived, HTTP-only, SameSite cookie that identifies the browser to the BFF. |
| **Server-side token store** | The location where the BFF keeps the access token, refresh token, and ID token, usually the HTTP session. |
| **Downstream propagation** | The BFF attaching a token to outgoing requests to internal APIs or resource servers. |
| **Token lifetime** | Access tokens should remain short; the BFF can refresh them using the refresh token stored server-side. |

## Trust boundaries

- The browser holds only the session cookie; it never sees the access token.
- The BFF holds tokens and is responsible for refresh, storage, and safe propagation.
- The authorization server issues tokens to the BFF's `client_id`.
- The downstream resource server validates the token and enforces its own audience/scope checks.
- The session cookie must be HTTP-only, secure in production, and SameSite-appropriate for the cross-origin posture.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Server-side authorized client store | `HttpSessionOAuth2AuthorizedClientRepository` |
| Token propagation to downstream | `BffTokenController` / `OAuth2AuthorizedClientRepository.loadAuthorizedClient` |
| Session-bound login | `oauth2Login()` with `.authorizedClientRepository(...)` |
| Cookie security | Servlet container session cookie configuration or Spring Session |

## Failure and attack patterns

- **Access token in browser storage** lets XSS steal it and call APIs directly.
- **No `HttpOnly` cookie** lets JavaScript read the session cookie.
- **No `SameSite` policy** opens CSRF-style session-riding across sites.
- **Storing tokens in a distributed cache without encryption** leaks them if the cache is compromised.
- **Long-lived server sessions** keep tokens alive after the user has logged out.

## Guarantees and limitations

- The lab explicitly wires `HttpSessionOAuth2AuthorizedClientRepository` so tokens are not persisted in a client-side `DefaultOAuth2AuthorizedClientRepository`.
- `/bff/health` is public; `/bff/downstream` requires an authenticated session and a stored authorized client.
- End-to-end BFF flow requires the IdP from LAB-010 and a browser to exercise the session cookie.
