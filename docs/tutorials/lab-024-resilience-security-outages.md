# LAB-024: Resilience and Security Outages

## Status

- Theory prerequisite: `docs/theory/resilience-security-outages.md`
- Implementation: `rest-api` module
- Tests: `ResilienceLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ResilienceLabTest'`

## Measurable objective

Wrap opaque-token introspection with a bounded timeout and a short-lived cache so that a downstream identity outage fails closed for unseen tokens while allowing brief continuity for tokens verified moments earlier. Tests must prove healthy access, fail-closed behavior during an outage, timeout-driven fail-closed behavior, and bounded cache-based continuity.

## Source artifact map

| File | Purpose |
|---|---|
| `DependencyOutageSimulator.java` | Test-controllable stand-in for a downstream identity dependency (`HEALTHY`, `SLOW`, `DOWN`) |
| `ResilientOpaqueTokenIntrospector.java` | Bounds the downstream call with a timeout, caches short-lived successful results, fails closed otherwise |
| `ResilienceSecurityConfig.java` | Isolated `SecurityFilterChain` for `/resilient/**` using the resilient introspector |
| `ResilienceController.java` | `/resilient/issue`, `/resilient/mode`, and `/resilient/data` endpoints |
| `ResilienceLabTest.java` | Healthy, outage, timeout, and cache-continuity scenarios |

## Exercises

1. Review `ResilientOpaqueTokenIntrospector` and explain why an uncached token during an outage must be rejected, not allowed.
2. Trace how the 200ms timeout in `callDownstreamWithTimeout` interacts with the `SLOW` simulator that sleeps for 1 second.
3. Run `ResilienceLabTest` and confirm that `outageAllowsContinuityForRecentlyVerifiedToken` only works because the token was introspected successfully before the outage began.
4. Explain what would happen if the cache TTL were set to one hour instead of five seconds, and why that is a security regression.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ResilienceLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| Healthy dependency, valid token | 200 |
| No token | 401 |
| Unknown token while healthy | 401 |
| Downstream `DOWN`, uncached token | 401 (fail closed) |
| Downstream `DOWN`, token verified moments earlier | 200 (bounded continuity) |
| Downstream `SLOW` beyond timeout, new token | 401 (timeout fail closed) |

## Production extension

- Replace `DependencyOutageSimulator` with a real HTTP client, timeout, and retry policy against an authorization server's introspection endpoint.
- Add a circuit breaker (for example, Resilience4j) so repeated failures stop issuing new calls for a cool-down period.
- Move the cache to a shared store (Redis) so all instances see the same degraded-mode state.
- Emit metrics and alerts when the introspector enters degraded mode.
- Add exponential backoff and jitter for retries against the identity provider.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*ResilienceLabTest'
BUILD SUCCESSFUL
ResilienceLabTest: 6 passed
```

## Next lab

LAB-025 — Delegated Access and Actor Tokens (or continue with the next unimplemented lab in `docs/progress.md`).
