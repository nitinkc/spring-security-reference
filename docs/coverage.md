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
| JWT custom filter | Implemented (educational only) | `common-auth` | Keep labeled as a filter-mechanics example, not a recommended path |
| OAuth2 resource server (JWT) | Verified | `ResourceServerSecurityConfig`, `ResourceServerJwtLabTest` | Add JWK rotation, unknown `kid`, discovery, and outage policy |
| Method security | Verified | `MethodSecurityConfig`, `AuthorizationServiceMethodSecurityLabTest` | Add domain-backed ownership and proxy-boundary integration tests |
| Browser sessions and fixation | Verified | `BrowserSecurityConfig`, `BrowserSessionLabTest` | Add cookie attributes, timeouts, and concurrent-session limits |
| CSRF protection | Verified | `BrowserSecurityConfig`, `BrowserCsrfLabTest` | Add SPA cookie repository and token rotation tests |
| CORS and security headers | Verified | `BrowserSecurityConfig`, `BrowserCorsHeadersLabTest` | Add HSTS and nonce-based CSP on an HTTPS origin |
| Local identity provider | Implemented (opt-in, not yet executed) | `infrastructure/idp/*`, `LocalIdentityProviderLabTest` | Run with Docker to move to Verified; then use Testcontainers in CI |
| Service-to-service client credentials | Implemented (configuration unit-tested) | `ClientCredentialsConfig`, `ClientCredentialsLabTest` | End-to-end token exchange and `RestClient` propagation with Docker |
| OAuth2/OIDC login | Implemented (configuration verified, IdP flow pending) | `OAuth2AuthConfig`, `OAuth2LoginConfigurationTest` | Run the end-to-end browser flow with Docker and add an opt-in integration test |
| API gateway | Verified | `gateway` module, `GatewayConfig`, `GatewayLabTest` | Spring Cloud Gateway with token relay, rate limiting, and real downstream proxy |
| JWK rotation and multiple issuers | Verified | `JwkLabKeyProvider`, `ResourceServerSecurityConfig` | Multi-tenant issuer resolver and JWK discovery |
| Token lifecycle (refresh/revocation) | Implemented (opt-in, not yet executed) | `TokenLifecycleLabTest` in `rest-api` (5 scenarios skip without Docker) | Run with Docker to move to Verified |
| Opaque token introspection | Verified | `OpaqueToken*LabTest` in `rest-api` | Replace in-process introspector with `NimbusOpaqueTokenIntrospector` against a real IdP |
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
