# LAB-028: Rate Limiting and Failure Policies

## Status

- Theory prerequisite: `docs/theory/rate-limiting-failure-policies.md`
- Implementation: `rest-api` module
- Tests: `RateLimitingLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*RateLimitingLabTest'`

## Measurable objective

Add a per-client token-bucket rate limiter that returns `429` with `Retry-After` when the bucket is empty, and expose explicit `fail-open` and `fail-closed` endpoints that choose availability or safety when a downstream dependency is down. Tests must prove burst limits, client isolation, refill, and both failure policies.

## Source artifact map

| File | Purpose |
|---|---|
| `RateLimitingService.java` | In-memory token bucket per `ip:method:path` key |
| `RateLimitingFilter.java` | `OncePerRequestFilter` that returns 429 when the bucket is empty |
| `RateLimitingConfig.java` | `SecurityFilterChain` for `/rate-limit/**` |
| `RateLimitingController.java` | Public, private, and `/fail/{open\|closed}` endpoints |
| `RateLimitingLabTest.java` | Burst, 429, isolated buckets, and fail-open/closed tests |

## Exercises

1. Trace `RateLimitingFilter.resolveClientKey()` and explain why `X-Forwarded-For` is preferred over `getRemoteAddr()` in proxied environments.
2. Run `RateLimitingLabTest.burstAllowsFiveRequestsThenThrottles()` and confirm the 6th response contains `Retry-After: 1`.
3. Compare `/rate-limit/fail/open` and `/rate-limit/fail/closed` when `DependencyOutageSimulator` is `DOWN`. Which should security-sensitive paths use?
4. Identify why `RateLimitingFilter` is placed before `AuthorizationFilter` in the chain.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*RateLimitingLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| First 5 requests to `/rate-limit/public` from one client | 200 |
| 6th request from same client within the same second | 429, `Retry-After: 1` |
| Request from a different client after the first is throttled | 200 |
| Wait 1 second, request again from throttled client | 200 |
| `/rate-limit/fail/open` when downstream is down | 200 `fallback` |
| `/rate-limit/fail/closed` when downstream is down | 503 `downstream unavailable` |

## Production extension

- Replace the in-memory bucket with Redis, Bucket4j, or a gateway-level rate limiter.
- Add sliding-window or leaky-bucket policies for stricter limits.
- Authenticate rate-limit keys using API keys or user IDs instead of IP for shared NAT scenarios.
- Move the failure-policy decision into a central policy engine that different paths can query.
- Add metrics and alerts for throttled requests and fail-open degradations.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*RateLimitingLabTest'
BUILD SUCCESSFUL
RateLimitingLabTest: 4 passed
```

## Next lab

LAB-029 — GraphQL Security.
