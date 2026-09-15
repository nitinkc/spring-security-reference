# LAB-010: Local Identity Provider

**Status:** Implemented and opt-in; **not yet executed** because this workstation had no running Docker daemon  
**Theory:** [Identity Provider Fundamentals](../theory/identity-provider.md)

## Objective

Provide a reproducible local IdP with a declarative realm, then confirm discovery metadata, PKCE support, audience mapping, and role claims from real issued tokens.

## Implementation map

| Artifact | Purpose |
|---|---|
| `infrastructure/idp/docker-compose.yml` | Keycloak 26.7.3 on port 8081 with realm import and health check |
| `infrastructure/idp/realm-export.json` | Realm, roles, clients, mappers, and lab users |
| `infrastructure/idp/README.md` | Start/stop commands and endpoints |
| `LocalIdentityProviderLabTest` | Opt-in verification that self-skips when the IdP is down |

Realm contract:

| Item | Value |
|---|---|
| Issuer | `http://localhost:8081/realms/spring-security-reference` |
| Public client | `spa-client` with PKCE `S256` |
| Confidential client | `api-client` with service account |
| Audience claim | `spring-security-reference-api` |
| Authorities claim | `roles` |
| Users | `labuser` (USER), `labadmin` (USER, ADMIN) |

## Exercises

1. Start the IdP:

   ```bash
   docker compose -f infrastructure/idp/docker-compose.yml up -d
   ```

2. Fetch the discovery document and locate the issuer, JWK URI, and token endpoint.
3. Run the opt-in test and confirm it now executes instead of skipping.
4. Request a token for `labadmin` and decode the payload; inspect `iss`, `aud`, `roles`, `exp`, and the header `kid`.
5. Repeat for `labuser` and confirm `ADMIN` is absent.
6. Submit a wrong password and confirm the provider returns 401 without a token.
7. Inspect the admin console and locate the redirect URI, PKCE attribute, and audience mapper.
8. Stop the IdP and confirm the test skips rather than fails.

## Verification

```bash
./gradlew :rest-api:test --tests '*LocalIdentityProviderLabTest'
./gradlew test
```

With the IdP stopped, the five scenarios report as skipped. With the IdP running, they must all pass.

## Attack checks

- Confirm the realm does not accept a wildcard redirect URI.
- Confirm a token issued for another audience would fail the LAB-009 validator.
- Confirm lab credentials exist only in this isolated compose environment.

## Production extension

Replace the lab realm with managed configuration, disable the password grant, enforce MFA, shorten token lifetimes, add key rotation, and document outage behavior. In CI, prefer Testcontainers so the realm starts and stops per run.

## Review

Complete the identity-provider and token-validation questions in the [SSO and Federation Quiz](../quizzes/federation.md).

**Next:** LAB-011 OAuth2 Authorization Code with PKCE
