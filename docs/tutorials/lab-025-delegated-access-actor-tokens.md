# LAB-025: Delegated Access and Actor Tokens

## Status

- Theory prerequisite: `docs/theory/delegated-access-actor-tokens.md`
- Implementation: `rest-api` module
- Tests: `DelegatedAccessLabTest`
- Verification: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*DelegatedAccessLabTest'`

## Measurable objective

Build a `/delegated/**` resource-server chain that accepts direct user tokens and delegated tokens carrying an RFC 8693 `act` claim, but only when the actor identity is in an explicit trust allow-list. Tests must prove direct access, trusted-actor delegated access, untrusted-actor rejection, expiry, and missing-token handling.

## Source artifact map

| File | Purpose |
|---|---|
| `DelegationJwkLabKeyProvider.java` | Single-issuer RSA signing key for the lab |
| `ActorAllowListValidator.java` | `OAuth2TokenValidator<Jwt>` that rejects tokens with an untrusted `act.sub` |
| `DelegatedAccessSecurityConfig.java` | Isolated `SecurityFilterChain` for `/delegated/**` composing timestamp and actor validators |
| `DelegatedAccessController.java` | `/delegated/data` endpoint that reports the effective subject and, if present, the acting party |
| `DelegatedAccessLabTest.java` | Direct, delegated, untrusted-actor, expired, and missing-token scenarios |

## Exercises

1. Review `ActorAllowListValidator` and explain why the actor must be checked even though the token signature is already valid.
2. Trace how `DelegatedAccessController` distinguishes a direct user action from a delegated one.
3. Run `DelegatedAccessLabTest` and confirm that `malicious-service` as an actor is rejected even with a validly signed token.
4. Describe how this lab's `act` claim relates to the LAB-019 token exchange client that produces delegated tokens.

## Commands

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*DelegatedAccessLabTest'
```

## Positive and negative test expectations

| Scenario | Expected |
|---|---|
| Direct token, no `act` claim | 200, `data for alice` |
| `act.sub=trusted-support-service` | 200, `data for alice via trusted-support-service` |
| `act.sub=malicious-service` | 401 |
| Expired token | 401 |
| Missing token | 401 |

## Production extension

- Support nested `act.act` chains for multi-hop delegation and audit each hop.
- Combine actor trust with actor-specific scope restrictions rather than a binary allow-list.
- Persist an audit trail that always records both subject and actor for delegated actions.
- Integrate with the LAB-019 token-exchange client so the actor claim is populated by a real authorization server rather than hand-built in tests.
- Add rate limits or step-up requirements for high-risk operations performed through delegation.

## Completion evidence

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home ./gradlew :rest-api:test --tests '*DelegatedAccessLabTest'
BUILD SUCCESSFUL
DelegatedAccessLabTest: 5 passed
```

## Next lab

LAB-026 — continue with the next unimplemented lab in `docs/progress.md`.
