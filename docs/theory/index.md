# Spring Security Theory

Theory pages explain protocols, threats, guarantees, and Spring Security internals without mixing in step-by-step exercises. Labs link back to these pages and contain implementation instructions and executable proof.

## Foundations

1. [Request authorization and filter chains](request-authorization.md)
2. [Authentication managers and providers](authentication-providers.md)
3. [Password storage and migration](password-storage.md)
4. [Method security](method-security.md)
5. [Security error boundaries](security-errors.md)

## Federation and distributed systems

Existing conceptual references remain grouped under Security until extracted during their implementation sessions:

- [OAuth2 and OIDC](../authentication/oauth2-auth.md)
- [SSO with OIDC and SAML](../authentication/sso-integration.md)
- [JWT and resource-server concepts](../authentication/jwt-tokens.md)
- [Authorization](../security/authorization.md)
- [Security use cases](../security/use-cases.md)

A theory page must not claim a mechanism is implemented. Consult the [Coverage Registry](../coverage.md) for evidence status.
