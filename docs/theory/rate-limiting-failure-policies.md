# Rate Limiting and Failure Policies

Security controls must survive real-world pressure. Rate limiting prevents a single caller from exhausting shared resources, and explicit failure policies decide whether the system protects availability by degrading gracefully or by refusing to operate without a trusted signal.

## Security objective

Bound resource consumption per client and IP, and make the fail-open or fail-closed policy explicit and observable so operators can choose availability or safety under load and during downstream outages.

## Core concepts

| Term | Meaning |
|---|---|
| **Token bucket** | A caller can burst up to a capacity, then refills at a steady rate. |
| **Client isolation** | Each client or IP has its own bucket so one abuser does not block legitimate traffic. |
| **Retry-After** | A 429 response tells a client when to reattempt, reducing retry storms. |
| **Fail closed** | A missing or failed security signal causes the request to be denied. Favours safety over availability. |
| **Fail open** | A missing or failed security signal causes a degraded but allowed path. Favours availability over strict enforcement. |
| **Policy as code** | The failure mode is a configuration choice, not an accidental side effect of an exception handler. |

## Trust boundaries

- The rate limiter runs before the expensive work, including authentication if the caller is unauthenticated, to reject abuse cheaply.
- Client identity for rate limiting is derived from `X-Forwarded-For` first, then `RemoteAddr`, because a reverse proxy is the trust boundary for IP.
- Fail-open and fail-closed paths are explicit endpoints so the policy is not hidden in a catch block.
- Security-related decisions continue to fail closed; only non-critical reads may be allowed to fail open.

## Spring Security mapping

| Concept | Spring Security / Spring API |
|---|---|
| Per-client rate limit | `OncePerRequestFilter` with an in-memory `RateLimitingService` bucket per key |
| IP extraction | `HttpServletRequest.getHeader("X-Forwarded-For")` and `getRemoteAddr()` |
| 429 with retry | `HttpServletResponse.setStatus(429)` and `Retry-After` header |
| Failure policy | `DependencyOutageSimulator` plus explicit `fail/{policy}` endpoint |
| Stateless policy endpoints | `SecurityFilterChain` with `permitAll` for the rate-limit and failure-policy paths |

## Failure and attack patterns

- **Shared bucket** lets one attacker consume the quota for all users.
- **No `Retry-After`** causes clients to retry immediately, amplifying the load.
- **IP spoofing without proxy trust** lets an attacker cycle headers and evade limits.
- **Implicit fail open** in an exception handler can silently authorize requests during outages.
- **Implicit fail closed** can take down a whole service because one dependency is slow.
- **Rate limiter as the only defense** does not stop distributed abuse; combine with WAF and CDN-level limits.

## Guarantees and limitations

- `RateLimitingService` keeps one bucket per `ip:method:path` key and refills one token per second up to a capacity of five.
- `RateLimitingFilter` rejects excess calls with `429` and a `Retry-After` header.
- `/rate-limit/fail/open` and `/rate-limit/fail/closed` make the failure policy explicit and observable.
- The lab uses in-memory storage. Production needs distributed rate limiting and centralized policy configuration.
