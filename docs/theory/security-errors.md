# Security Error Boundaries

## Security objective

Return stable client behavior while revealing as little as possible about credentials, accounts, authorities, policies, and implementation details.

## Spring Security model

Many security failures happen in the servlet filter chain before controller invocation. `ExceptionTranslationFilter` converts them through two extension points:

| Situation | Spring API | Typical API status |
|---|---|---|
| Authentication absent or invalid | `AuthenticationEntryPoint` | 401 |
| Authenticated but unauthorized | `AccessDeniedHandler` | 403 |

Controller advice handles exceptions raised after controller dispatch; it does not replace filter-boundary handlers.

Browser chains may redirect to login while stateless API chains return JSON. Configure behavior per chain and client contract.

## Safe error schema

A bounded schema can contain status, stable machine code, generic message, and normalized request path. It should omit exception messages, stack traces, token data, authorities, policy expressions, account existence, and internal class names.

Detailed diagnostics belong in protected logs using bounded error categories and correlation identifiers. Credentials, assertions, authorization codes, cookies, and full tokens must never be logged.

## Trust and failure cases

- Returning 403 for every missing credential
- Serializing parser exception text
- Returning granted or required authorities
- Redirecting API clients unexpectedly
- High-cardinality or sensitive diagnostic fields
- Different login failures enabling enumeration

## Transfer

FastAPI exception handlers and NestJS exception filters provide equivalent contracts. Spring's pre-controller entry point and denied-handler boundary is framework-specific.

Continue with [LAB-005](../tutorials/lab-005-security-errors.md).
