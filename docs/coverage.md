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
| OIDC SSO | Verified | `OAuth2AuthConfig`, `CustomOidcUserService`, `OidcAuthoritiesMapperTest` | End-to-end login and userInfo integration with the local IdP |
| SAML relying party | Verified | `saml-auth` module, `SamlAuthConfig`, `SamlRelyingPartyLabTest` | LAB-018 through LAB-020: signed/unsigned assertions, attribute mapping, and single logout |
| TOTP/MFA | Theory | Hardcoded demonstration hook | Enrollment, replay, recovery, and step-up lab |
| WebAuthn/passkeys | Planned | None | Registration and authentication lab |
| REST authorization | Implemented | `rest-api` | Production-chain MockMvc tests |
| GraphQL security | Verified | `GraphQLConfig`, `GraphQLController`, `GraphQLSecurityLabTest` | Resolver and complexity tests |
| gRPC security | Verified | `GrpcAuthInterceptor`, `GrpcMtlsInterceptor`, `GrpcSecurityLabTest` | Metadata auth and mTLS tests |
| WebSocket security | Planned | Placeholder validation | Handshake and destination tests |
| Service-to-service OAuth2 | Implemented | `ClientCredentialsConfig` (LAB-014), `TokenExchangeConfig` (LAB-019) | End-to-end client credentials and token exchange with Docker |
| Delegated access (actor tokens) | Verified (lab) | `ActorAllowListValidator`, `DelegatedAccessSecurityConfig`, `DelegatedAccessLabTest` | Nested `act.act` chains and actor-specific scope restriction |
| mTLS/workload identity | Verified | `MtlsAuthConfig`, `MtlsLabTest` | Real TLS listener, certificate rotation, and revocation checks |
| API keys and quotas | Verified | `ApiKeyAuthConfig`, `ApiKeyAuthenticationFilter`, `ApiKeysAndQuotasLabTest` | See LAB-026 for hashed key lifecycle |
| API key lifecycle | Verified | `SecureApiKeyService`, `SecureApiKeyLifecycleConfig`, `ApiKeyLifecycleLabTest` | Vault-backed rotation, audit, and bcrypt/Argon2 for high-sensitivity keys |
| Gateway/BFF/token relay | Planned | None | Browser-to-gateway-to-service lab |
| Resilience and security outages | Verified (lab) | `ResilientOpaqueTokenIntrospector`, `DependencyOutageSimulator`, `ResilienceLabTest` | See LAB-028 for per-client rate limits and explicit fail-open/closed |
|| Rate limiting and failure policies | Verified | `RateLimitingService`, `RateLimitingFilter`, `RateLimitingLabTest` | Distributed bucket, gateway-level limits, and policy engine |
| Auditing and observability | Planned | None | Privacy-safe event and outage lab |
| Container/Kubernetes security | Planned | None | Deployment and secret-rotation lab |
| Authorization server | Planned | None | LAB-047 with PKCE, clients, consent, persistence, and rotation |
| SCIM/identity lifecycle | Planned | None | LAB-048 provisioning, reconciliation, and deprovisioning |
| Active Directory/LDAPS | Planned | LDAP foundation only | LAB-049 TLS, AD mapping, outage, and negative trust tests |
| X.509 authentication | Planned | mTLS theory only | LAB-050 certificate identity, revocation, and proxy-boundary tests |
| Reactive WebFlux security | Planned | Servlet examples only | LAB-051 reactive chain, method security, and context tests |
| Spring Cloud Gateway security | Planned | Gateway/BFF theory only | LAB-052 route authorization and constrained token relay |
| External authorization policy | Planned | Local authorization only | LAB-053 decision/enforcement, cache, and outage tests |
| Multi-tenant federation | Verified (lab) | `TenantAwareJwtDecoder`, `TenantJwkLabKeyProvider`, `TenantLabTest` | See LAB-027 for row-level object authorization |
|| Tenant and object authorization | Verified | `TenantObjectService`, `TenantObjectSecurityConfig`, `TenantObjectAuthorizationLabTest` | Per-tenant schema, row-level security, and encrypted data at rest |
| Kafka security | Planned | Generic messaging lab only | LAB-055 workload identity, ACL, replay, and tenant tests |
| Build supply chain/SBOM | Planned | Gradle build only | LAB-056 locking, verification, SBOM, scanning, and provenance |
| Data protection/privacy | Planned | Logging rules only | LAB-057 encryption, rotation, retention, and redaction tests |
| API/proxy abuse defense | Planned | General threat labs only | LAB-058 SSRF, forwarded-header, upload, size, and redirect tests |
