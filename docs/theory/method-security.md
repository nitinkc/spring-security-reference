# Method Security

## Security objective

Protect business operations at the resource-owning service boundary, including calls from controllers, GraphQL, messaging, scheduled jobs, and other beans.

Request authorization cannot protect alternate invocation paths or make ownership decisions requiring domain data.

## Spring Security model

`@EnableMethodSecurity` registers authorization interceptors around Spring-managed beans. `@PreAuthorize` evaluates before invocation using the current authentication and method arguments.

| Responsibility | Spring API |
|---|---|
| Enable interception | `@EnableMethodSecurity` |
| Pre-invocation rule | `@PreAuthorize` |
| Current identity | `authentication` in SpEL |
| Named argument | `#username` with Java `-parameters` |
| Complex decision | `AuthorizationManager` or policy service |
| Test identity | `@WithMockUser` |

## Proxy boundary

Method security is normally proxy-based. A call from one method to another on `this` does not cross the proxy and is not intercepted. Constructing the service with `new` also bypasses Spring.

Keep security-sensitive operations on a separately injected service boundary and test the Spring-managed bean.

## Trust and failure cases

- Self-invocation bypass
- Test invokes an unproxied object
- Complex domain rules hidden in unreadable SpEL
- User-supplied identifiers treated as ownership proof
- HTTP rules assumed to protect message or scheduled invocation

## Transfer

Other frameworks often require explicit policy calls or guards. Authorization at the resource-owning layer is transferable; Spring proxy and SpEL behavior are Spring-specific.

Continue with [LAB-004](../tutorials/lab-004-method-security.md).
