# OIDC SSO

OpenID Connect (OIDC) is an identity layer on top of OAuth 2.0. It lets a client application obtain identity information about the authenticated user in the form of an **ID token**, while keeping the password at the identity provider.

## Security objective

Authenticate end users through an external identity provider and convert the provider's claims into application-specific authorities, without the application ever handling the user's credentials.

## Core concepts

| Term | Meaning |
|---|---|
| **ID token** | A JWT signed by the IdP containing claims about the authenticated user. |
| **UserInfo endpoint** | An OAuth2-protected endpoint that returns the same or additional user claims as JSON. |
| **`sub`** | Stable, opaque subject identifier for the user at a given IdP. |
| **`roles` / `groups` claims** | Common sources for application authorization decisions. |
| **`nonce`** | A value bound to the client session to prevent replay of an ID token. |
| **`acr` / `amr` claims** | Indicators of the authentication method and assurance level used. |

## Trust boundaries

- The IdP owns the user's password, MFA, and session.
- The client application owns:
  - The registration, including exact redirect URIs and PKCE settings.
  - The mapping from IdP claims to local authorities.
  - Its own session or token storage.
- The ID token signature, issuer, audience, and expiry must be verified by `oauth2ResourceServer` or by the `oauth2Login` machinery.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Client registration | `ClientRegistrationRepository` / `InMemoryClientRegistrationRepository` |
| Authorization Code + PKCE | `DefaultOAuth2AuthorizationRequestResolver` + `OAuth2AuthorizationRequestCustomizers.withPkce()` |
| OIDC user handling | `OAuth2UserService<OidcUserRequest, OidcUser>` |
| Authority mapping | Custom `OidcUserService` that wraps `DefaultOidcUserService` and remaps claims |
| Filter chain | `HttpSecurity#oauth2Login(...)` with `.userInfoEndpoint(...)` |

## Failure and attack patterns

- **No PKCE on public clients** allows authorization code interception.
- **Unvalidated ID tokens** allow an attacker to forge a login.
- **Trusting the `email` claim without verification** lets attackers register with an unverified address.
- **Over-provisioning roles** from the IdP without scrubbing can grant unintended access.
- **Missing `nonce`** enables replay of an ID token from another transaction.

## Guarantees and limitations

- Spring Security verifies the ID token signature, issuer, expiry, and audience by default when configured with `oauth2Login`.
- The `OidcAuthoritiesMapper` in this lab converts the provider's `roles` claim into `ROLE_` authorities. In production, claim names and authority prefixes vary by IdP.
- End-to-end login against a real IdP requires Docker to start the Keycloak realm from LAB-010.
