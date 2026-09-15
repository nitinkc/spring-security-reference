# Resilience and Security Outages

Authentication and authorization often depend on a remote service: an introspection endpoint, a JWK set, or a policy decision point. When that dependency is slow or unreachable, the security decision must still be correct. The wrong failure mode — silently allowing every request — turns an availability problem into an authorization bypass.

## Security objective

Ensure that a downstream identity dependency outage degrades availability, not security. Unknown or unverifiable credentials must be rejected; only credentials verified moments earlier may continue to work briefly through a bounded cache.

## Core concepts

| Term | Meaning |
|---|---|
| **Fail closed** | On error or timeout, the system denies the request by default. |
| **Fail open** | On error or timeout, the system allows the request by default — almost always the wrong default for security decisions. |
| **Bounded timeout** | A hard limit on how long the system waits for a downstream identity call before treating it as failed. |
| **Short-lived cache** | A small time-boxed cache of results already verified successfully, used only to smooth over brief outages, not to replace verification. |
| **Degraded mode** | A reduced-functionality mode where previously verified sessions continue to work but new, unverifiable ones are rejected. |

## Trust boundaries

- A token that has never been verified must never be accepted just because the introspection endpoint is unreachable.
- A cache of verified results must have a short TTL so a revoked token cannot remain valid indefinitely because of stale cache entries.
- Timeouts must be bounded so a hung downstream call cannot exhaust threads or block the whole application.
- Failure handling must be observable: outages should be logged and alertable, not silently swallowed.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Custom fail-closed introspection | Implement `OpaqueTokenIntrospector` and wrap the delegate call |
| Bounded timeout | `CompletableFuture.supplyAsync(...).get(timeout, unit)` around the downstream call |
| Reject on failure | Throw `BadOpaqueTokenException` so Spring Security returns 401 |
| Isolate the chain | `HttpSecurity#securityMatcher("/resilient/**")` |

## Failure and attack patterns

- **Fail-open on timeout** turns a denial-of-service against the identity provider into free access to every protected route.
- **Unbounded cache** keeps a revoked token valid long after the real authorization server would have rejected it.
- **No timeout at all** lets a hung downstream call exhaust request-handling threads.
- **Swallowing exceptions** and returning success hides operational outages from monitoring while extending the security exposure window.
- **Cache poisoning** if the cache key is not the exact opaque token, or if unauthenticated calls can populate it.

## Guarantees and limitations

- `ResilientOpaqueTokenIntrospector` bounds the downstream call to 200ms and treats a timeout or thrown exception as failure.
- On failure, it checks a 5-second, in-memory cache of tokens introspected successfully moments earlier; if present, access continues; otherwise the request is rejected with 401.
- `DependencyOutageSimulator` stands in for a real network client so tests can force `HEALTHY`, `SLOW`, or `DOWN` behavior deterministically.
- This is a lab-scale illustration: production systems should also add circuit breakers, retries with backoff, structured outage alerts, and a distributed cache shared across instances.
