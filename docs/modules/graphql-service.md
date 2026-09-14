# GraphQL Service

## Current status

The module compiles with Spring GraphQL and Spring Security dependencies, but its security interceptor is not implemented. The coverage status remains Planned; it must not be treated as a secured GraphQL service.

## Security boundary

GraphQL requires authorization below the single HTTP endpoint. Resolver and service rules must protect queries, mutations, fields, object ownership, and tenant boundaries. HTTP authentication alone is insufficient.

## Required labs

- **LAB-029:** Resolver and field authorization, including alias and batch bypass tests.
- **LAB-030:** Depth, complexity, pagination, and amplification limits.

## Completion criteria

- Authentication reaches resolver execution through a trusted security context.
- Sensitive fields and mutations have positive and negative tests.
- Object and tenant authorization occurs in the resource-owning layer.
- Introspection exposure is an explicit environment decision.
- Query cost and error responses are bounded and observable.
- The placeholder interceptor is removed or replaced.

Run module checks with:

```bash
./gradlew :graphql-service:test
```
