# Delegated Access and Actor Tokens

Some requests are not made directly by the user; they are made by a trusted intermediary acting on the user's behalf, such as a support tool, an automation service, or a downstream microservice acting after a token exchange (LAB-019). RFC 8693 models this with an `act` (actor) claim that records who is acting, distinct from `sub`, who the action is performed for.

## Security objective

Preserve both the original subject and the acting party through a delegation chain, and only accept delegation from actors the resource server explicitly trusts. An untrusted or forged actor must not be able to impersonate a user by simply adding an `act` claim to a token.

## Core concepts

| Term | Meaning |
|---|---|
| **Subject (`sub`)** | The identity a request is performed for — the original user or resource owner. |
| **Actor (`act`)** | The identity of the party currently making the call on the subject's behalf. |
| **Delegation chain** | A sequence of actors that may be nested (`act.act`) when delegation passes through multiple hops. |
| **Actor allow-list** | The set of actor identities a resource server trusts to present delegated tokens. |
| **On-behalf-of access** | Authorization decisions that consider both the subject's permissions and the actor's trustworthiness. |

## Trust boundaries

- The `act` claim must be inside the signed token; a header-based actor claim is trivially forgeable.
- The resource server must verify the token's signature before trusting any claim, including `act`.
- An actor identity must be checked against an explicit allow-list; the presence of an `act` claim is not itself authorization.
- Authorization decisions may need to consider the actor's own permissions in addition to the subject's, depending on the operation's sensitivity.

## Spring Security mapping

| Concept | Spring Security API |
|---|---|
| Custom actor validation | `OAuth2TokenValidator<Jwt>` implementation composed with `DelegatingOAuth2TokenValidator` |
| Reading nested claims | `Jwt#getClaimAsMap("act")` |
| Isolating the delegated chain | `HttpSecurity#securityMatcher("/delegated/**")` |
| Role mapping unaffected by delegation | `JwtGrantedAuthoritiesConverter` on the subject's `roles` claim |

## Failure and attack patterns

- **No actor validation** lets any client add an `act` claim and impersonate a user through an unauthorized path.
- **Actor trust based on unsigned data** (for example, a header) allows trivial forgery.
- **Ignoring the actor in authorization decisions** can let a low-trust automation account perform actions that should require a human actor.
- **Missing chain-length limits** allow arbitrarily deep, hard-to-audit delegation chains.
- **Logging without the actor** makes an audit trail useless for distinguishing a user's own action from a delegated one.

## Guarantees and limitations

- `ActorAllowListValidator` rejects a token whose `act.sub` value does not appear in `DelegatedAccessSecurityConfig.TRUSTED_ACTORS`.
- A token without an `act` claim is treated as a direct user action.
- The lab uses a single hard-coded allow-list and a single-hop actor; production systems should also support nested `act.act` chains, per-actor scoping, and audit-log enrichment.
- Combining LAB-019 (token exchange) with this lab reflects a full delegation flow: a client exchanges a subject token for a downstream token that carries an `act` claim, and the downstream resource server verifies the actor before granting access.
