# API Gateway

## Security objective

An API gateway is a reverse proxy that terminates TLS, authenticates and authorizes requests, and forwards them to the right downstream service. It must not become a place where tokens are logged, replayed, or exposed to the browser.

## What the gateway owns

| Concern | Owned by the gateway |
|---|---|
| TLS termination | Yes |
| Authentication of the caller | Yes |
| coarse authorization | Yes |
| rate limiting and WAF | Yes |
| routing | Yes |
| fine-grained domain authorization | No |

The gateway enforces who can call which route; the downstream service still owns what the caller may do with its resources.

## Token handling at the gateway

- Validate the token at the gateway.
- Forward the token to downstream services that need it for their own authorization.
- Do not log the full token.
- Do not return the token in responses unless that is an explicit design.
- Consider token exchange so the downstream service receives an audience-scoped token.

## Spring Cloud Gateway versus servlet proxy

Spring Cloud Gateway is a reactive, non-blocking gateway. A servlet-based proxy with `RestClient` or `WebClient` is easier to test and reason about for learning. Both require the same decisions:

- Which routes need authentication?
- Which claims/scopes grant access?
- Which headers are forwarded?
- How is the downstream token supplied?

## Trust and failure cases

- Logging bearer tokens
- Returning tokens to the browser
- Using the gateway as the only authorization point and giving downstream services no validation
- Skipping audience validation for downstream tokens
- Allowing unauthenticated direct access to downstream services
- Not validating TLS certificates on egress
- Storing tokens in gateway session state

Continue with [LAB-016](../tutorials/lab-016-api-gateway.md).
