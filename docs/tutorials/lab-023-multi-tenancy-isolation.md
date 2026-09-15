# LAB-023: Multi-Tenancy and Tenant Isolation

## Status

- Theory prerequisite: `docs/theory/multi-tenancy-isolation.md`
- Implementation: `rest-api` module
- Tests: `TenantLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*TenantLabTest'`

## Measurable objective

Build a `/tenant/**` resource-server chain with a `TenantAwareJwtDecoder` that uses the `tenant` claim to select the correct per-tenant verification key. Tests must prove that tenant A and tenant B tokens are accepted, an expired token, a missing `tenant` claim, and a token signed with the wrong tenant's key are all rejected.

## Source artifact map

| File | Purpose |
|---|---|
| `TenantJwkLabKeyProvider.java` | Generates per-tenant RSA signing keys for `tenant-a` and `tenant-b` |
| `TenantAwareJwtDecoder.java` | Reads the `tenant` claim from the unsigned JWT, then delegates to the matching `NimbusJwtDecoder` |
| `TenantSecurityConfig.java` | Isolated `SecurityFilterChain` for `/tenant/**` with the tenant decoder and role mapping |
| `TenantController.java` | `/tenant/data` endpoint that echoes the tenant from the JWT |
| `TenantLabTest.java` | Generates tokens and asserts per-tenant access and isolation |

## Exercises

1. Review `TenantAwareJwtDecoder` and explain why it reads the `tenant` claim before verifying the signature.
2. Trace how `TenantJwkLabKeyProvider` keeps each tenant's signing material separate.
3. Run `TenantLabTest` and confirm that a token with a forged `tenant=a` claim but signed with `tenant-b`'s key is rejected.
4. Describe how a real repository would use the `tenant` claim from the JWT to scope database queries.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*TenantLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| Valid `tenant-a` token on `/tenant/data` | 200, `data for tenant-a` |
| Valid `tenant-b` token on `/tenant/data` | 200, `data for tenant-b` |
| No token | 401 |
| Expired token | 401 |
| Token without `tenant` claim | 401 |
| `tenant=a` claim signed with `tenant-b` key | 401 |

## Production extension

- Replace in-process keys with an allow-listed issuer directory and JWK set discovery per tenant.
- Add issuer and audience validation per tenant.
- Use Spring's `JwtIssuerAuthenticationManagerResolver` for multi-issuer resolution as the tenant scale grows.
- Implement row-level data scoping in repositories with `WHERE tenant_id = ?` and tenant-aware audit columns.
- Add cross-tenant access logging and anomaly detection for tokens that attempt to switch tenants.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*TenantLabTest'
BUILD SUCCESSFUL
TenantLabTest: 6 passed
```

## Next lab

LAB-024 — Resilience and Security Outages.
