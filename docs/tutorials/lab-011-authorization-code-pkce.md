# LAB-011: OAuth2 Authorization Code with PKCE

**Status:** Implemented and unit-tested; full IdP interaction requires Docker  
**Theory:** [Authorization Code with PKCE](../theory/authorization-code-pkce.md)

## Objective

Configure a Spring `oauth2Login()` client against the LAB-010 Keycloak realm, enforce PKCE, exact redirect URIs, and `openid` profile/email/roles scopes, and exercise the callback validation path.

## Implementation map

| Artifact | Purpose |
|---|---|
| `OAuth2AuthConfig` | Client registration and login filter chain for `http://localhost:8081/realms/spring-security-reference` |
| `OAuth2AuthenticationSuccessHandler` | Placeholder that saves the principal name and delegates to default redirect handling |
| `OAuth2ClientApplication` | Boot entry point for the module |
| `OAuth2LoginConfigurationTest` | Unit tests verifying registration shape without the IdP |

Registration values:

| Field | Value |
|---|---|
| Registration id | `spring-security-reference` |
| Client id | `spa-client` |
| Grant type | `authorization_code` |
| Authentication method | `none` (public client) |
| Redirect URI | `http://localhost:8080/login/oauth2/code/spring-security-reference` |
| PKCE | `requireProofKey(true)` |
| Scopes | `openid`, `profile`, `email`, `roles` |

## Exercises

1. Run the unit test and confirm the registration requires a proof key and points at the local Keycloak endpoints.
2. Start the IdP:

   ```bash
   docker compose -f infrastructure/idp/docker-compose.yml up -d
   ```

3. Start the `oauth2-auth` module on `http://localhost:8080`.
4. Browse `http://localhost:8080/` and observe the redirect to the Keycloak login form.
5. Authenticate as `labuser`/`lab-user-password` and observe the callback.
6. Inspect the authenticated session and confirm `SUB` and `roles` claims are populated.
7. Capture the authorization request URL and confirm it contains `state`, `nonce`, `code_challenge`, and `response_type=code`.
8. Intercept the callback, change `state`, and confirm the application rejects it.

## Verification

```bash
./gradlew :oauth2-auth:test
```

IdP-bound integration will be added once Docker is available.

## Attack checks

- Confirm the callback validates `state` before token exchange.
- Confirm the redirect URI is an exact, pre-registered value.
- Confirm the client is public and does not ship a secret.
- Confirm the ID token `nonce` matches the authorization request.

## Production extension

Move the client to `ClientRegistrations.fromOidcIssuerLocation(discovery)` with a trusted issuer, require consent where appropriate, enable back-channel logout, store refresh tokens server-side, and rotate keys on a schedule.

## Review

Complete the OIDC login questions in the [SSO and Federation Quiz](../quizzes/federation.md).

**Next:** LAB-012 Token Lifecycle
