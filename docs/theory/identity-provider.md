# Identity Provider Fundamentals

## Security objective

An identity provider (IdP) centralises authentication, credential policy, multi-factor requirements, session management, and token issuance. Applications become relying parties that validate assertions instead of storing passwords.

## What the IdP owns

| Concern | Owned by the IdP |
|---|---|
| Credential storage and policy | Yes |
| Multi-factor and step-up | Yes |
| IdP session lifetime | Yes |
| Token issuance and signing keys | Yes |
| Discovery metadata and JWK set | Yes |
| Application authorization decisions | No |
| Object and tenant ownership rules | No |

Centralised authentication does not centralise authorization. Each application still authorizes its own resources.

## Discovery and trust

OIDC providers publish `/.well-known/openid-configuration` containing the issuer, authorization, token, UserInfo, and JWK endpoints plus supported grants, response types, and PKCE methods.

A relying party must configure the trusted issuer. Discovery then supplies endpoints for that issuer. Discovery must never be driven by a value taken from an untrusted token or request.

## Realm design decisions

| Decision | Why it matters |
|---|---|
| Public versus confidential client | Public clients cannot hold secrets and require PKCE |
| Redirect URI registration | Exact matching prevents code interception |
| Audience mapping | Lets an API reject tokens minted for other APIs |
| Role/group claim mapping | Defines the contract the API maps through an allow list |
| Token and session lifetimes | Bounds replay and revocation lag |
| Service accounts | Separates workload identity from user identity |

## Reproducibility

A learning or CI environment should import realm configuration declaratively so clients, roles, users, and mappers are identical on every start. Bootstrap administrator credentials in such an environment are lab-only values and must never appear in shared or production systems.

## Trust and failure cases

- Default administrator credentials reused outside an isolated environment
- Wildcard or loosely matched redirect URIs
- Missing audience mapper, allowing cross-API token reuse
- Password grant enabled for convenience and then left enabled
- Long-lived access tokens with no revocation strategy
- Realm configuration drift between environments
- No plan for IdP outage or signing-key rotation

## Transfer

Any provider that implements OIDC discovery exposes the same contract, so relying-party configuration is portable. Provider-specific realm, client, and mapper models are not.

Continue with [LAB-010](../tutorials/lab-010-local-identity-provider.md).
