# LAB-029: GraphQL Security

## Status

- Theory prerequisite: `docs/theory/graphql-security.md`
- Implementation: `graphql-service` module
- Tests: `GraphQLSecurityLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :graphql-service:test --tests '*GraphQLSecurityLabTest'`

## Measurable objective

Secure a Spring for GraphQL service so that a sensitive field (`salary`) is only returned to `ADMIN` users, and enforce query complexity and depth limits that reject overly large operations before resolvers run.

## Source artifact map

| File | Purpose |
|---|---|
| `GraphqlServiceApplication.java` | Boot entry point and component scan |
| `GraphQLConfig.java` | `@EnableMethodSecurity`, `permitAll` HTTP filter, and query instrumentation |
| `GraphQLController.java` | `hello`, `me`, and `salary` resolvers with `@PreAuthorize` on `salary` |
| `User.java` | GraphQL `User` type |
| `schema.graphqls` | Schema with `User { name, salary }` and `Query { hello, me }` |
| `GraphQLSecurityLabTest.java` | Field access, role-based denial, and complexity limit tests |

## Exercises

1. Review `schema.graphqls` and identify which fields can be requested on `User`.
2. Run `GraphQLSecurityLabTest.userCannotReadSalary()` and confirm the error is in `$.errors` while `$.data.me.name` still returns.
3. Explain why `complexQueryIsRejected()` fails before any resolver is invoked.
4. Compare this field-level model with a REST API that returns the same user object; which leaks more by default?

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :graphql-service:test --tests '*GraphQLSecurityLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| `{ hello }` | `data.hello = "Hello from GraphQL"` |
| `{ me { name } }` | `data.me.name = "alice"` |
| `{ me { name salary } }` as USER | `data.me.salary = null`, `errors` present |
| `{ me { name salary } }` as ADMIN | `data.me.salary = 100000`, no errors |
| `{ hello me { name salary } }` | `errors` present because complexity > 3 |

## Production extension

- Add an owner-based `@PostAuthorize` check for object-level authorization on the `me` resolver.
- Disable or restrict GraphQL introspection in production.
- Use a DataLoader or `@BatchMapping` to avoid N+1 resolver calls.
- Move from `@PreAuthorize` on resolvers to a domain-driven `@PostFilter` or a custom `DataFetcher` decorator that logs field access.
- Add query-parsing metrics and alert on high rejection rates.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :graphql-service:test --tests '*GraphQLSecurityLabTest'
BUILD SUCCESSFUL
GraphQLSecurityLabTest: 5 passed
```

## Next lab

LAB-030 — gRPC Security.
