# Token Exchange and Delegated Access

OAuth 2.0 Token Exchange (RFC 8693) lets a client trade one token for another, usually to obtain a token with a narrower audience or different scope for a downstream call. It is the standard pattern for **service-to-service delegation on behalf of a user**.

## Security objective

Allow an upstream service to call a downstream service using a token that is scoped to the downstream service, without sending the user's full-access token or the service's own long-lived client-credentials token.

## Core concepts

| Term | Meaning |
|---|---|
| **Subject token** | The token representing the party on whose behalf the call is made. |
| **Actor token** | The token representing the calling service, when the caller is different from the subject. |
| **Requested token type** | The kind of token to return (e.g., `urn:ietf:params:oauth:token-type:access_token`). |
| **Audience** | The intended recipient of the issued token, typically a downstream service identifier. |
| **Delegation** | A token issued for the downstream audience that still preserves the original subject. |

## Trust boundaries

- The authorization server validates the subject token, audience, and scopes.
- The calling service must authenticate itself with client credentials or another credential.
- The downstream service receives a token it can validate independently, scoped only to its own audience.
- The upstream service must not send the subject token to the downstream service unless the downstream audience is the same.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Client registration | `ClientRegistration` with `AuthorizationGrantType.TOKEN_EXCHANGE` |
| Token exchange provider | `TokenExchangeOAuth2AuthorizedClientProvider` |
| Subject token resolver | `TokenExchangeOAuth2AuthorizedClientProvider#setSubjectTokenResolver` |
| Access token client | `RestClientTokenExchangeTokenResponseClient` |
| Authorized client manager | `AuthorizedClientServiceOAuth2AuthorizedClientManager` |
| Outgoing propagation | `OAuth2ClientHttpRequestInterceptor` on a `RestClient` |

## Failure and attack patterns

- **Sending a user's token to a downstream service** defeats audience scoping and may expose high-privilege tokens.
- **No audience check** at the token-exchange endpoint can mint tokens for any service.
- **Missing actor token** can obscure the true calling service in audit logs.
- **Token exchange without transport security** leaks subject and client secrets.

## Guarantees and limitations

- The configuration in this lab sets up the Spring Security beans and the `ClientRegistration` for token exchange.
- End-to-end exchange requires the IdP from LAB-010 to be running and a `subjectTokenResolver` that provides a real access token.
- A production deployment should add a custom `TokenExchangeGrantRequestEntityConverter` to set the `audience` and `requested_token_type` parameters explicitly.
