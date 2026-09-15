# GraphQL Security

GraphQL shifts the request surface from many endpoints to a single `/graphql` endpoint where the caller chooses fields and nesting depth. That surface must be authorized at field level and bounded for complexity and depth, otherwise one cheap query can expose too much data or exhaust the service.

## Security objective

Protect a single GraphQL endpoint with field-level authorization and deterministic limits on query size, so callers cannot read sensitive fields without authority and cannot submit overwhelming queries.

## Core concepts

| Term | Meaning |
|---|---|
| **Field-level authorization** | A resolver checks the caller's authorities before returning a specific field, not just the top-level query. |
| **Method security** | `@PreAuthorize` on controller resolver methods makes the authorization check part of the bean invocation. |
| **Query complexity** | Total number of fields selected in an operation; used to reject overly broad queries. |
| **Query depth** | Maximum number of nested selection sets; used to reject deep recursion or traversal attacks. |
| **Schema-first** | SDL schema files in `classpath:graphql/*.graphqls` define the shape and the Java resolvers implement it. |

## Trust boundaries

- The HTTP layer can be open because individual resolvers enforce `hasRole` or `hasAuthority` checks.
- A field that is not authorized returns an error and `null` for that field, not a hard 403 for the entire response.
- Query complexity and depth are evaluated before resolvers run, so rejected queries do not reach the data layer.
- The schema is the contract: if a field is not in the schema, it cannot be requested.

## Spring Security mapping

| Concept | Spring Security / Spring API |
|---|---|
| Field-level authorization | `@PreAuthorize` on `@SchemaMapping` resolver methods with `@EnableMethodSecurity` |
| Method security activation | `@EnableMethodSecurity` in `GraphQLConfig` |
| Query complexity limit | `MaxQueryComplexityInstrumentation` from `graphql-java` |
| Query depth limit | `MaxQueryDepthInstrumentation` from `graphql-java` |
| Schema wiring | `GraphQlSourceBuilderCustomizer` from `org.springframework.boot.autoconfigure.graphql` |
| Testing | `MockMvc` posting JSON to `/graphql` with `@WithMockUser` |

## Failure and attack patterns

- **Authorization at the HTTP endpoint only** lets a caller query every field on any type once they are authenticated.
- **Missing field-level checks** allows `me { salary }` for ordinary users.
- **Deep queries** like `me { manager { manager { ... } } }` cause N+1 loads and stack exhaustion.
- **Wide queries** like `users { name salary projects { owner secrets } }` fetch huge graphs with one request.
- **Introspection enabled in production** exposes the schema to attackers.
- **Field-level exceptions leaking stack traces** reveal resolver implementation details.

## Guarantees and limitations

- `GraphQLController.salary` is protected by `@PreAuthorize("hasRole('ADMIN')")`.
- `MaxQueryComplexityInstrumentation(3)` rejects the combined `hello me { name salary }` query because it selects four fields.
- `MaxQueryDepthInstrumentation(5)` sets an upper bound for nested selections.
- The lab uses a static salary map. Production should validate the caller, the object owner, and the field sensitivity.
- Introspection is not disabled in the lab; production should turn it off or restrict it.
