# API Keys and Resource Quotas

API keys are a simple, stateless authentication credential for machine clients. They work well for service-to-service calls, integrations, and scripts, but they are also easy to leak, replay, and abuse. A complete API-key design pairs authentication with rate limiting, rotation, and audit.

## Security objective

Allow stateless machine access while limiting the blast radius of a leaked key and preventing a single caller from exhausting shared resources.

## Core concepts

| Term | Meaning |
|---|---|
| **API key** | A long, random secret issued to a client and presented with every request, usually in a header. |
| **Prefix** | A short, non-secret identifier embedded in the key so support can look it up without storing the full secret. |
| **Rate limit** | A cap on the number of requests a caller may make in a time window, enforced per key, per IP, or per user. |
| **Token bucket** | A rate-limiting algorithm that refills a fixed number of tokens over time and rejects requests when the bucket is empty. |
| **Sliding window** | A rate-limiting algorithm that counts only the requests inside the trailing window and expires old entries as time passes. |

## Trust boundaries

- The client must keep the key secret; anyone with the key can make requests until the key is revoked.
- The server validates the key without an external identity provider round-trip, so the repository must be authoritative.
- Keys should be hashed before storage; plaintext storage is acceptable only for short-lived lab credentials.
- Rate limits can be enforced at the edge, in the application, or in the database; the closest to the caller provides the most resilient defense.
- Authorization still applies after authentication: a key may be valid but not have the required role.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Extract key from request | `request.getHeader("X-API-Key")` in a custom `OncePerRequestFilter` |
| Map key to authorities | `ApiKeyRepository` plus `ApiKeyAuthenticationToken` |
| Enforce per-key quota | `ApiKeyRateLimiter` sliding-window counter |
| Scope the filter chain | `HttpSecurity#securityMatcher("/apikey/**")` |
| Role-based access | `authorizeHttpRequests` with `hasAnyAuthority` / `hasAuthority` |

## Failure and attack patterns

- **Plaintext key storage** exposes every secret if the database is dumped.
- **No key rotation** lets a leaked key remain useful indefinitely.
- **Missing rate limits** allow brute force, enumeration, and resource exhaustion.
- **Logging the full key** in access logs or error messages leaks it to anyone with log access.
- **Key in URL query parameters** appears in browser history, proxies, and server logs.
- **Single shared key** across all clients prevents revocation of one client without breaking others.

## Guarantees and limitations

- The lab issues two in-memory keys: one with `ROLE_USER` and one with `ROLE_ADMIN`, each allowed 10 requests per second.
- `ApiKeyAuthenticationFilter` only inspects requests for `/apikey/**` and does not interfere with other chains.
- `ApiKeyRateLimiter` uses a sliding window stored in process memory; it is not distributed and does not survive a restart.
- Real production keys should be hashed, scoped, rotated, and stored with metadata such as issued-to, expiry, and last used.
