# LAB-020: Backend-for-Frontend (BFF) Token Handling

## Status

- Theory prerequisite: `docs/theory/bff-token-handling.md`
- Implementation: `oauth2-auth` module
- Tests: `BffTokenLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :oauth2-auth:test`

## Measurable objective

Explicitly use a server-side `HttpSessionOAuth2AuthorizedClientRepository` for the `oauth2Login()` client, expose a BFF `/bff/downstream` endpoint that propagates the access token to downstream calls, and ensure the browser-facing `/bff/health` route is reachable without authentication.

## Source artifact map

| File | Purpose |
|---|---|
| `BffTokenConfig.java` | Defines `HttpSessionOAuth2AuthorizedClientRepository` |
| `BffTokenController.java` | `/bff/health` (public) and `/bff/downstream` (authenticated) |
| `OAuth2AuthConfig.java` | Wires the authorized client repository into `oauth2Login()` and adds `/bff/health` to permitAll |
| `BffTokenLabTest.java` | Verifies the repository, public health, and protected downstream routes |

## Exercises

1. Review `BffTokenConfig` and explain why `HttpSessionOAuth2AuthorizedClientRepository` is the right choice for a BFF.
2. Trace how `OAuth2AuthConfig` uses the `authorizedClientRepository` in `oauth2Login`.
3. Run `BffTokenLabTest` and confirm that `/bff/downstream` requires authentication.
4. Identify the cookie attributes that must be set for the BFF session cookie in production.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :oauth2-auth:test
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| `GET /bff/health` unauthenticated | 200 `bff-ready` |
| `GET /bff/downstream` unauthenticated | 302 redirect to the OAuth2 login entry point |
| `OAuth2AuthorizedClientRepository` bean | Is an `HttpSessionOAuth2AuthorizedClientRepository` |

## Production extension

- Add a real downstream call and a `RestClient` that reads the stored access token from the session.
- Configure the session cookie with `Secure`, `HttpOnly`, `SameSite`, and a short `Max-Age`.
- Store sessions in Redis or a database with encrypted token payloads.
- Add refresh-token handling and automatic downstream token refresh before expiry.
- Use Spring Cloud Gateway as the BFF with token relay and session cookie support.

## Completion evidence

```text
./gradlew :oauth2-auth:test
BUILD SUCCESSFUL
BffTokenLabTest: 3 passed
```

## Next lab

LAB-021 — Service Identity and mTLS.
