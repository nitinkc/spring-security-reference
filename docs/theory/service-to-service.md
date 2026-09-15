# Service-to-Service and Client Credentials

## Security objective

A service that calls another service must authenticate as a workload rather than a person. The client credentials grant is the standard OAuth2 flow for this, and the caller should not ship a user’s browser session to the backend.

## Why user delegation is wrong here

- A user’s access token often has scopes for the frontend, not the downstream service.
- A user token tied to a session cannot outlive it.
- The downstream service should not receive the user’s full identity claims for internal calls.

## Client credentials flow

```text
Service A             Authorization Server            Service B
   |                          |                         |
   | -- client_id, client_secret, scope=service-b ----> |
   |                          |                         |
   | <------------------ access_token ------------------ |
   |                          |                         |
   | ------- Authorization: Bearer <token> -----------> |
   |                          |                         |
   <---------------- response --------------------------- |
```

The access token represents the workload, not a person. Service B validates the token using the shared issuer.

## Spring Security model

| Responsibility | Spring API |
|---|---|
| Client registration | `ClientRegistration` with `CLIENT_CREDENTIALS` grant |
| Authorized client manager | `OAuth2AuthorizedClientManager` with `clientCredentials` provider |
| Token propagation | `OAuth2ClientHttpRequestInterceptor` on `RestClient` or `WebClient` |
| WebClient reactive | `ServerOAuth2AuthorizedClientExchangeFilterFunction` |
| Service B validation | `oauth2ResourceServer().jwt()` or `.opaqueToken()` |

## Security considerations

- Store `client_secret` in a secret manager, not source code.
- Use mTLS or DPoP when the environment demands stronger sender binding.
- Cache access tokens and refresh them before `exp` to avoid per-request token requests.
- Scope client tokens to the minimum needed by the called service.
- Validate `aud` on the receiving side so a token for one service cannot access another.

## Trust and failure cases

- Long-lived client tokens
- Reusing a user’s token for service calls
- No audience validation on the receiver
- Client secret checked into source control
- Not rotating service client secrets
- Allowing a client to request scopes broader than its role
- Calling internal services over plaintext

Continue with [LAB-014](../tutorials/lab-014-service-to-service.md).
