# Spring Security Theory

Theory pages explain protocols, threats, guarantees, and Spring Security internals without mixing in step-by-step exercises. Labs link back to these pages and contain implementation instructions and executable proof.

## Foundations

1. [Request authorization and filter chains](request-authorization.md)
2. [Authentication managers and providers](authentication-providers.md)
3. [Password storage and migration](password-storage.md)
4. [Method security](method-security.md)
5. [Security error boundaries](security-errors.md)
6. [Browser sessions and session fixation](browser-sessions.md)
7. [Cross-site request forgery](csrf.md)
8. [CORS and security headers](cors-and-headers.md)
9. [JWT resource server](jwt-resource-server.md)
10. [Identity provider fundamentals](identity-provider.md)
11. [Authorization Code with PKCE](authorization-code-pkce.md)
12. [Token lifecycle](token-lifecycle.md)
13. [Opaque token introspection](opaque-token-introspection.md)
14. [Service-to-service and client credentials](service-to-service.md)
15. [JWK rotation and multiple issuers](jwk-rotation.md)
16. [API gateway](api-gateway.md)

## Federation and distributed systems

Existing conceptual references remain grouped under Security until extracted during their implementation sessions:

- [OAuth2 and OIDC](../authentication/oauth2-auth.md)
- [SSO with OIDC and SAML](../authentication/sso-integration.md)
- [JWT and resource-server concepts](../authentication/jwt-tokens.md)
- [Authorization](../security/authorization.md)
- [Security use cases](../security/use-cases.md)

A theory page must not claim a mechanism is implemented. Consult the [Coverage Registry](../coverage.md) for evidence status.
