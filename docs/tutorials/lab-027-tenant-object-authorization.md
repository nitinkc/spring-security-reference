# LAB-027: Tenant and Object Authorization

## Status

- Theory prerequisite: `docs/theory/tenant-object-authorization.md`
- Implementation: `rest-api` module
- Tests: `TenantObjectAuthorizationLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*TenantObjectAuthorizationLabTest'`

## Measurable objective

Add object-level authorization on top of the existing tenant-aware JWT decoder. A document has `tenant` and `owner` attributes. Only the owner, or a same-tenant admin, can read it. Cross-tenant and same-tenant non-owner users must be denied.

## Source artifact map

| File | Purpose |
|---|---|
| `Document.java` | JPA entity with `id`, `tenant`, `owner`, `content` |
| `DocumentRepository.java` | Spring Data JPA repository |
| `TenantObjectService.java` | Writes ownership from the JWT; enforces tenant and object access |
| `TenantObjectController.java` | `/tenant-obj/documents` POST and GET |
| `TenantObjectSecurityConfig.java` | Isolated `/tenant-obj/**` chain using `TenantAwareJwtDecoder` and role converter |
| `TenantObjectAuthorizationLabTest.java` | Owner, non-owner, other-tenant, admin, and missing-token tests |

## Exercises

1. Trace how `TenantObjectService.getDocument()` uses both the `tenant` claim and the `owner` field before returning data.
2. Explain why `Document.tenant` and `Document.owner` are written from the JWT and not from the request body.
3. Run `TenantObjectAuthorizationLabTest` and confirm that `bob` (`tenant-a`) is denied `alice`'s document while `carol` (`tenant-b`) and a `tenant-b` admin are also denied.
4. Identify where the 403/404 distinction matters and whether the lab should return 404 for missing documents in all tenant cases.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*TenantObjectAuthorizationLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| Owner reads own document | 200 |
| Same-tenant non-owner | 403 |
| Other-tenant user | 403 |
| Same-tenant admin | 200 |
| Missing token | 401 |

## Production extension

- Move the authorization check into a custom `PermissionEvaluator` or domain-driven `@PostAuthorize` expression.
- Use row-level security in PostgreSQL or a per-tenant schema with tenant in the connection context.
- Add audit logging for denied object access attempts, especially cross-tenant denials.
- Prevent object ID enumeration by returning 404 for all unauthorized or missing resources unless the caller has tenant admin rights.
- Encrypt sensitive object content at rest with per-tenant keys.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*TenantObjectAuthorizationLabTest'
BUILD SUCCESSFUL
TenantObjectAuthorizationLabTest: 5 passed
```

## Next lab

LAB-028 — Rate Limiting and Failure Policies.
