# Multi-Tenancy and Tenant Isolation

A multi-tenant application serves many organisations from the same deployment. Each tenant must be authenticated, authorised, and separated at the data layer. A single tenant's compromise should not grant access to another tenant's resources.

## Security objective

Use tenant identity inside the token to select the correct trust material and to drive data-scoped authorisation, so that a request for tenant A can never be validated by tenant B's keys or reach tenant B's data.

## Core concepts

| Term | Meaning |
|---|---|
| **Tenant** | An isolated organisational boundary such as a customer, business unit, or region. |
| **Tenant-aware decoder** | A `JwtDecoder` that selects the JWK set, issuer, or validation policy based on a tenant claim in the token. |
| **Tenant claim** | A token attribute such as `tenant` or `tid` that identifies the tenant that issued the token. |
| **Tenant isolation** | Enforcing that a token from one tenant cannot be validated or used to access another tenant's data. |
| **Data scoping** | Every data query includes a tenant predicate so the database returns only rows owned by the caller's tenant. |

## Trust boundaries

- The token's `tenant` claim must be selected before validation because the validator needs the right key and issuer.
- The tenant value must come from a cryptographically signed token, never from a client-controlled header.
- Each tenant has its own signing keys and optional issuer and audience.
- The resource server must reject a token signed with the wrong tenant's key, even if the `tenant` claim is forged.
- The application layer must not rely on the URL or a header for tenant identity; it uses the authenticated token.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Extract tenant before validation | Custom `JwtDecoder` that parses `tenant` claim from the unsigned JWT header/payload, then delegates to a per-tenant `NimbusJwtDecoder` |
| Per-tenant JWK source | `ImmutableJWKSet` per tenant, selected from a `Map<String, NimbusJwtDecoder>` |
| Map `roles` claim to authorities | `JwtGrantedAuthoritiesConverter` with `setAuthoritiesClaimName("roles")` and `setAuthorityPrefix("ROLE_")` |
| Scope the tenant chain | `HttpSecurity#securityMatcher("/tenant/**")` |
| Read tenant in controller | `@AuthenticationPrincipal Jwt jwt` and `jwt.getClaim("tenant")` |

## Failure and attack patterns

- **Tenant from header** lets an attacker present a token for one tenant while asking for another's data.
- **Shared key across tenants** means a token forged for tenant A is accepted as tenant B.
- **Tenant claim after validation** forces the application to trust a claim that may have been validated with the wrong key.
- **Missing tenant validation** accepts tokens from an unknown or deleted tenant.
- **Row-level scoping missing** in repositories can leak data across tenants even when authentication is correct.

## Guarantees and limitations

- `TenantAwareJwtDecoder` selects the per-tenant `NimbusJwtDecoder` by reading the `tenant` claim before signature verification.
- Tokens signed with a different tenant's key fail validation and return 401.
- The lab uses two in-process keys; production would use a trusted issuer directory, key rotation, and a tenant allow-list.
- Data-layer scoping is simulated by the controller echoing the tenant; real repositories would enforce `WHERE tenant_id = ?`.
