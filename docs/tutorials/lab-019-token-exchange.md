# LAB-019: Token Exchange and Delegated Access

## Status

- Theory prerequisite: `docs/theory/token-exchange.md`
- Implementation: `oauth2-auth` module
- Tests: `TokenExchangeLabTest`, `ClientCredentialsLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :oauth2-auth:test`

## Measurable objective

Register an OAuth2 client for RFC 8693 token exchange, configure a `TokenExchangeOAuth2AuthorizedClientProvider` and a separate `RestClient` for delegated outbound calls, and verify that the client credentials and token-exchange managers are both wired without bean ambiguity.

## Source artifact map

| File | Purpose |
|---|---|
| `OAuth2AuthConfig.java` | Adds `token-exchange-client` to the `ClientRegistrationRepository` |
| `TokenExchangeConfig.java` | `TokenExchangeOAuth2AuthorizedClientProvider`, manager, and `delegationRestClient` |
| `ClientCredentialsConfig.java` | `clientCredentialsAuthorizedClientManager` and `serviceClient` |
| `ClientCredentialsLabTest.java` | Existing LAB-014 tests, now uses `@Qualifier` to disambiguate managers |
| `TokenExchangeLabTest.java` | Verifies the new token-exchange registration, manager, and `RestClient` |

## Exercises

1. Review `OAuth2AuthConfig` and locate the `token-exchange-client` registration.
2. Inspect `TokenExchangeConfig` and list the beans it contributes.
3. Explain why `@Qualifier` is necessary for both `RestClient` and `OAuth2AuthorizedClientManager` beans.
4. Identify the parameters that are still missing for an end-to-end token exchange (audience, requested token type, subject token source).

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :oauth2-auth:test
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| `token-exchange-client` registered | `AuthorizationGrantType.TOKEN_EXCHANGE`, token URI under the local Keycloak issuer, scope `spring-security-reference-api` |
| `tokenExchangeAuthorizedClientManager` | Not null, distinct from the client-credentials manager |
| `delegationRestClient` | Not null, wired to the token-exchange manager via `OAuth2ClientHttpRequestInterceptor` |
| Existing client-credentials tests | Still pass with the new beans present |

## Production extension

- Add a custom `TokenExchangeGrantRequestEntityConverter` to include the downstream `audience` and `requested_token_type`.
- Implement a `subjectTokenResolver` that extracts the current user's access token from the `SecurityContext`.
- Add an end-to-end test that runs against the local IdP and verifies the exchanged token audience.
- Use separate `client_id` and `client_secret` values for the token-exchange client.

## Completion evidence

```text
./gradlew :oauth2-auth:test
BUILD SUCCESSFUL
TokenExchangeLabTest: 3 passed
OidcAuthoritiesMapperTest: 3 passed
OAuth2LoginConfigurationTest: 4 passed
ClientCredentialsLabTest: 2 passed
```

## Next lab

LAB-020 — Backend-for-Frontend (BFF) Token Handling.
