# Request Authorization and Filter Chains

## Security objective

Authenticate a caller when required, then decide whether that identity may access a requested resource. Public routes are explicit exceptions, not the default.

## HTTP semantics

- **401 Unauthorized:** valid authentication is missing or invalid.
- **403 Forbidden:** authentication exists, but authority is insufficient.
- **200-class response:** request passed the boundary; business rules may still deny an operation.

## Spring Security model

`FilterChainProxy` owns a list of `SecurityFilterChain` instances. It selects the first chain whose `securityMatcher` matches the request. Chains are not merged.

Inside the selected chain, `AuthorizationFilter` evaluates request rules in declaration order. A broad rule placed before a narrow rule can make the narrow rule unreachable.

| Responsibility | Spring API |
|---|---|
| Select a chain | `FilterChainProxy`, `securityMatcher` |
| Define policy | `authorizeHttpRequests` |
| Match a request | `requestMatchers` |
| Require identity | `authenticated()` |
| Require role/authority | `hasRole`, `hasAuthority`, `AuthorizationManager` |
| Hold current identity | `SecurityContext` |

`hasRole("ADMIN")` normally checks for `ROLE_ADMIN`; `hasAuthority` compares the exact value.

## Trust and failure cases

- Overlapping chains select an unintended policy.
- Matcher ordering exposes a restricted route.
- A forwarded header creates an untrusted principal.
- Request authorization is mistaken for object ownership authorization.
- Anonymous and insufficient-authority failures are conflated.

Request rules should be complemented by method or domain authorization when a resource can be reached through multiple protocols or code paths.

## Transfer

FastAPI dependencies and Node/Nest middleware or guards solve the same boundary problem. First-match chain selection, `SecurityContext`, and Spring authorization DSL behavior are Spring-specific.

Continue with [LAB-001](../tutorials/lab-001-request-authorization.md).
