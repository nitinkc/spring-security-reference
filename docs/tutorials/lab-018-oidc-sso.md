# LAB-018: OIDC Login with `oauth2Login()`

## Status

- Theory prerequisite: `docs/theory/oidc-sso.md`
- Implementation: `oauth2-auth` module
- Tests: `OidcAuthoritiesMapperTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :oauth2-auth:test`

## Measurable objective

Wire a Spring Security `oauth2Login()` client for OpenID Connect and convert IdP `roles` claims into local `ROLE_` authorities. Verify the claim-to-authority mapping with in-memory test tokens.

## Source artifact map

| File | Purpose |
|---|---|
| `oauth2-auth/src/main/java/.../oauth2auth/OAuth2AuthConfig.java` | `ClientRegistrationRepository` and `oauth2Login()` filter chain for the SPA and API clients |
| `oauth2-auth/src/main/java/.../oauth2auth/CustomOidcUserService.java` | `OidcUserService` that delegates to `OidcUserService` and remaps authorities |
| `oauth2-auth/src/main/java/.../oauth2auth/OidcAuthoritiesMapper.java` | Converts the `roles` claim to `ROLE_` authorities with a default fallback |
| `oauth2-auth/src/test/java/.../oauth2auth/OidcAuthoritiesMapperTest.java` | Unit tests for list, comma-separated, and missing `roles` |
| `OAuth2LoginConfigurationTest.java` | Existing registration-shape and filter tests from LAB-011 |

## Exercises

1. Review `OAuth2AuthConfig` and confirm the SPA client uses `openid` scope, `AuthorizationGrantType.AUTHORIZATION_CODE`, `ClientAuthenticationMethod.NONE`, and `requireProofKey(true)`.
2. Trace how `CustomOidcUserService` overrides the default `OidcUserService` and applies `OidcAuthoritiesMapper`.
3. Run `OidcAuthoritiesMapperTest` and explain why the default authority is `ROLE_USER`.
4. Identify the in-memory and end-to-end tests that still require the IdP from LAB-010.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :oauth2-auth:test
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| `roles` claim is a list `["USER","ADMIN"]` | Authorities include `ROLE_USER` and `ROLE_ADMIN` |
| `roles` claim is a comma-separated string | Authorities include `ROLE_USER` and `ROLE_ADMIN` |
| No `roles` claim | Default authority is `ROLE_USER` |
| Existing `OAuth2LoginConfigurationTest` | Passes unchanged |

## Production extension

- Add an `OidcUserRequest` integration test against the real Keycloak userInfo endpoint once Docker is running.
- Map `group` / `groups` claims to authorities for providers that do not use `roles`.
- Add logout handling through the `end_session_endpoint` returned in the provider configuration metadata.
- Store the client secret for `api-client` in a secrets manager and out of source control.

## Completion evidence

```text
./gradlew :oauth2-auth:test
BUILD SUCCESSFUL
OidcAuthoritiesMapperTest: 3 passed
OAuth2LoginConfigurationTest: 4 passed
```

## Next lab

LAB-019 — Token Exchange and Delegated Access.
