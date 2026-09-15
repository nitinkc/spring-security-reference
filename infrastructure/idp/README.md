# Local Identity Provider (LAB-010)

Reproducible Keycloak instance for the OAuth2, OIDC, and SSO labs. Credentials here are lab-only and must never be reused elsewhere.

## Start and stop

```bash
docker compose -f infrastructure/idp/docker-compose.yml up -d
docker compose -f infrastructure/idp/docker-compose.yml logs -f keycloak
docker compose -f infrastructure/idp/docker-compose.yml down -v
```

## Endpoints

| Purpose | URL |
|---|---|
| Admin console | http://localhost:8081/admin |
| Realm issuer | http://localhost:8081/realms/spring-security-reference |
| Discovery | http://localhost:8081/realms/spring-security-reference/.well-known/openid-configuration |
| JWK set | http://localhost:8081/realms/spring-security-reference/protocol/openid-connect/certs |

## Realm contents

| Item | Value |
|---|---|
| Realm | `spring-security-reference` |
| Public client | `spa-client` (Authorization Code + PKCE) |
| Confidential client | `api-client` (Client Credentials) |
| API audience claim | `spring-security-reference-api` |
| Authorities claim | `roles` (realm roles) |
| Users | `labuser` (USER), `labadmin` (USER, ADMIN) |

## Obtain a test token

```bash
curl -s -X POST \
  http://localhost:8081/realms/spring-security-reference/protocol/openid-connect/token \
  -d grant_type=password \
  -d client_id=spa-client \
  -d username=labadmin \
  -d password=lab-admin-password | python3 -m json.tool
```

The password grant is enabled only to make this lab scriptable. LAB-011 uses Authorization Code with PKCE, which is the correct browser flow.

## Verification test

```bash
./gradlew :rest-api:test --tests '*LocalIdentityProviderLabTest'
```

The test skips itself when the IdP is not reachable, so `./gradlew test` remains runnable without Docker.
