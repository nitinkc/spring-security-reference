# Security Coverage

This registry prevents documentation-only features from being mistaken for working labs. Use the [Lab Roadmap](labs.md) to advance each capability through the defined statuses.

| Capability | Current status | Evidence | Next proof required |
|---|---|---|---|
| Filter-chain request authorization | Verified | `MultiAuthSecurityConfig` and `RequestAuthorizationLabTest` | Extend with invalid bearer token and overlapping-chain attack tests |
| REST security error contract | Verified | JSON entry point/denied handler and exact response tests | Add invalid-token parser errors and correlation IDs |
| Custom authentication provider | Verified | `CustomAuthenticationProvider` and `LoginAuthenticationLabTest` | Add rate limits and audit events in later abuse labs |
| Password storage and migration | Verified | `PasswordSecurityConfig`, `AuthServicePasswordMigrationLabTest` | Add persistent atomic migration and work-factor benchmark |
| JDBC authentication | Implemented | `jdbc-auth` | Database-backed authentication tests |
| LDAP authentication | Implemented | `ldap-auth` | Embedded LDAP integration tests |
| JWT custom filter | Implemented | `common-auth` | Replace primary path with resource server lab |
| Method security | Verified | `MethodSecurityConfig`, `AuthorizationServiceMethodSecurityLabTest` | Add domain-backed ownership and proxy-boundary integration tests |
| CSRF and browser sessions | Theory | Documentation snippets | Cookie-based positive and attack lab |
| CORS and security headers | Planned | None | Browser-origin and header tests |
| OAuth2/OIDC login | Theory | `oauth2-auth` is skeletal | Local IdP login lab |
| OAuth2 resource server | Theory | Dependencies and snippets | Issuer/audience/JWK tests |
| OIDC SSO | Theory | [SSO trust, session, logout, and threat model](authentication/sso-integration.md) | LAB-010 through LAB-016, including two clients |
| SAML SSO | Theory | [SAML relying-party and assertion model](authentication/sso-integration.md) | LAB-017 through LAB-020 with negative assertion tests |
| TOTP/MFA | Theory | Hardcoded demonstration hook | Enrollment, replay, recovery, and step-up lab |
| WebAuthn/passkeys | Planned | None | Registration and authentication lab |
| REST authorization | Implemented | `rest-api` | Production-chain MockMvc tests |
| GraphQL security | Planned | Placeholder interceptor | Resolver and complexity tests |
| gRPC security | Planned | Skeleton module | Metadata auth and mTLS tests |
| WebSocket security | Planned | Placeholder validation | Handshake and destination tests |
| Service-to-service OAuth2 | Planned | None | Client Credentials and delegation labs |
| mTLS/workload identity | Theory | Documentation snippets | Two-service certificate lab |
| Gateway/BFF/token relay | Planned | None | Browser-to-gateway-to-service lab |
| Auditing and observability | Planned | None | Privacy-safe event and outage lab |
| Container/Kubernetes security | Planned | None | Deployment and secret-rotation lab |
| Authorization server | Planned | None | LAB-047 with PKCE, clients, consent, persistence, and rotation |
| SCIM/identity lifecycle | Planned | None | LAB-048 provisioning, reconciliation, and deprovisioning |
| Active Directory/LDAPS | Planned | LDAP foundation only | LAB-049 TLS, AD mapping, outage, and negative trust tests |
| X.509 authentication | Planned | mTLS theory only | LAB-050 certificate identity, revocation, and proxy-boundary tests |
| Reactive WebFlux security | Planned | Servlet examples only | LAB-051 reactive chain, method security, and context tests |
| Spring Cloud Gateway security | Planned | Gateway/BFF theory only | LAB-052 route authorization and constrained token relay |
| External authorization policy | Planned | Local authorization only | LAB-053 decision/enforcement, cache, and outage tests |
| Multi-tenant federation | Planned | Tenant authorization lab only | LAB-054 trusted issuer/relying-party resolution and isolation |
| Kafka security | Planned | Generic messaging lab only | LAB-055 workload identity, ACL, replay, and tenant tests |
| Build supply chain/SBOM | Planned | Gradle build only | LAB-056 locking, verification, SBOM, scanning, and provenance |
| Data protection/privacy | Planned | Logging rules only | LAB-057 encryption, rotation, retention, and redaction tests |
| API/proxy abuse defense | Planned | General threat labs only | LAB-058 SSRF, forwarded-header, upload, size, and redirect tests |
