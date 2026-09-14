# Authentication Managers and Providers

## Security objective

Convert untrusted credentials into a trusted authenticated principal only after validation. Token or session issuance must consume the authenticated result, never raw request identity or authority values.

## Spring Security model

A controller or authentication filter creates an unauthenticated `Authentication` and submits it to `AuthenticationManager`. `ProviderManager` selects an `AuthenticationProvider` whose `supports` method accepts that authentication type.

The provider validates credentials and either:

- returns an authenticated `Authentication` containing server-derived authorities, or
- throws an `AuthenticationException`, commonly `BadCredentialsException`.

The authenticated result should not retain a raw password.

| Responsibility | Spring API |
|---|---|
| Authentication request | `UsernamePasswordAuthenticationToken.unauthenticated` |
| Provider coordination | `AuthenticationManager`, `ProviderManager` |
| Credential validation | `AuthenticationProvider` |
| Generic failure | `BadCredentialsException` |
| Trusted result | Authenticated `UsernamePasswordAuthenticationToken` |

## Account enumeration

Unknown users and wrong passwords should expose the same public status and body. Implementations should also perform bounded password-hash work for unknown users to reduce obvious timing differences. Rate limits and monitoring remain necessary.

## Trust and failure cases

- JWT issued without calling the manager
- Role derived from username pattern or request parameter
- Provider returns raw credentials
- Unknown user produces a distinguishable response
- Unsupported provider claims another credential type
- Logs contain passwords or reusable tokens

## Transfer

FastAPI authentication dependencies and Passport/Nest strategies have equivalent responsibilities. `ProviderManager` selection and Spring `Authentication` objects are framework-specific.

Continue with [LAB-002](../tutorials/lab-002-secure-login.md).
