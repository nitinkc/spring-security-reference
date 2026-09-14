# Authentication Testing Reference

Security tests must prove both access and denial. A passing happy path alone does not establish a security boundary.

## Test layers

| Layer | Purpose |
|---|---|
| Unit | Credential validators, claim mapping, and permission decisions |
| MVC slice | HTTP status, matcher rules, CSRF, headers, and error payloads |
| Application integration | Real filter chain, providers, persistence, and profiles |
| External integration | IdP, LDAP, SAML, certificates, broker, and network behavior |

## Minimum matrix

Test anonymous, valid identity, insufficient authority, malformed credential, expired credential, wrong issuer or audience where relevant, and the mechanism-specific replay or bypass case.

Use `spring-security-test` request processors such as `user()`, `jwt()`, and `csrf()` only when the layer intentionally bypasses credential parsing. At least one integration test must exercise the real parser or provider.

Run REST tests with:

```bash
./gradlew :rest-api:test
```

The first executable example is `RequestAuthorizationLabTest`; LAB-001 upgrades it to load the production filter chain. See [Testing Authentication](../examples/testing-auth.md) for the session workflow.
