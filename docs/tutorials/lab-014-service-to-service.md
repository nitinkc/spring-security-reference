# LAB-014: Service-to-Service and Client Credentials

**Status:** Implemented (configuration unit-tested)  
**Theory:** [Service-to-Service and Client Credentials](../theory/service-to-service.md)

## Objective

Configure a machine client that uses the client credentials grant and propagates access tokens through `RestClient` to downstream APIs.

## Implementation map

| Artifact | Purpose |
|---|---|
| `OAuth2AuthConfig` | Now includes the `api-client` client-credentials registration alongside `spa-client` |
| `ClientCredentialsConfig` | `OAuth2AuthorizedClientManager` for client credentials and a `RestClient` with `OAuth2ClientHttpRequestInterceptor` |
| `ClientCredentialsLabTest` | Verifies the `api-client` registration, manager, and service client wiring |

Registration values:

| Field | Value |
|---|---|
| Registration id | `api-client` |
| Client id | `api-client` |
| Grant type | `client_credentials` |
| Authentication method | `client_secret_basic` |
| Secret | `lab-api-client-secret` |
| Scope | `spring-security-reference-api` |

## Exercises

1. Inspect the `api-client` registration and confirm `client_secret_basic` is used.
2. Confirm the `OAuth2AuthorizedClientManager` is configured for client credentials only.
3. Review the `RestClient` interceptor that attaches the token.
4. With Docker running, start the local IdP and call:

   ```bash
   curl -s -X POST http://localhost:8081/realms/spring-security-reference/protocol/openid-connect/token \
     -d grant_type=client_credentials \
     -d client_id=api-client \
     -d client_secret=lab-api-client-secret \
     -d scope=spring-security-reference-api
   ```

5. Use that token to call a protected resource and observe the audience check.

## Verification

```bash
./gradlew :oauth2-auth:test
```

The unit test verifies registration wiring without the IdP. End-to-end token exchange and propagation require Docker.

## Attack checks

- Confirm the client secret does not appear in the final application logs.
- Confirm the downstream API validates `aud`.
- Confirm the client cannot request arbitrary scopes.
- Confirm user tokens are not propagated from the browser to backend services.

## Production extension

Move the client secret to a secret store, use mTLS or DPoP, implement a bounded token cache, and enforce audience and scope on the receiving resource server.

## Review

Complete the service-to-service questions in the [SSO and Federation Quiz](../quizzes/federation.md).

**Next:** LAB-015 API Gateway
