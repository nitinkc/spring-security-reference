# Tenant and Object Authorization

Tenant-level isolation (LAB-023) decides which JWK set to trust and which tenant a token represents. Object authorization adds a second layer: even within a tenant, a principal should only touch the rows, files, or resources they own or are explicitly allowed to manage.

## Security objective

Enforce that every data read or write is scoped to both the authenticated tenant and the specific object owner, with a controlled exception for tenant-scoped administrators.

## Core concepts

| Term | Meaning |
|---|---|
| **Tenant trust boundary** | All verification material, data connection, and policy for one tenant is kept separate from another. |
| **Object ownership** | A row or resource carries an `owner` and `tenant` attribute derived from the request that created it. |
| **Role-based override** | A tenant administrator may read or manage objects in the same tenant without being the owner, but not across tenants. |
| **Fail closed** | Cross-tenant access and non-owner access are denied, even when the token itself is valid. |

## Trust boundaries

- Tenant identity is extracted from a signed claim (`tenant`) only after the token is verified with that tenant's key.
- Object ownership is written at creation time and is never accepted from the client as a parameter.
- A request is authorized only when all three hold:
  - Token is valid.
  - Token's tenant matches the object's tenant.
  - Principal is the object owner or a same-tenant administrator.
- Cross-tenant identifiers return the same denial status as missing identifiers to avoid information leakage.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Tenant-aware JWT decoder | Reuse `TenantAwareJwtDecoder` from LAB-023 |
| Role-to-authority mapping | `JwtAuthenticationConverter` with `roles` -> `ROLE_*` |
| Object authorization | `@AuthenticationPrincipal Jwt` plus a service-layer check in `TenantObjectService` |
| Data model | JPA `Document` entity with `tenant`, `owner`, `content` |

## Failure and attack patterns

- **Missing ownership check** lets any same-tenant user read or modify another user's data.
- **Tenant in body parameter** allows a caller to claim any tenant because the parameter is not verified against the token.
- **Admin without tenant binding** gives one tenant's admin access to all tenants.
- **Different 404 vs 403 for cross-tenant** leaks which object IDs exist in other tenants.
- **Owner from client input** lets a caller create objects on behalf of another user or tenant.

## Guarantees and limitations

- `TenantObjectService` reads `tenant` and `subject` from the verified JWT, not from client input.
- The service rejects cross-tenant access and non-owner non-admin access with `AccessDeniedException`.
- The lab uses an in-memory H2 database. Production must use a per-tenant schema, row-level security, or encrypted column storage.
- `ResponseStatusException` for missing documents returns 404, but for cross-tenant or unauthorized access returns 403 uniformly.
