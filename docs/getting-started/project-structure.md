# Project Structure

This page explains the modular architecture and folder structure of the Spring Security Reference project.

## 🏗️ **Overview**

The project uses a layered modular architecture for clear separation of concerns:

```
api-service → common-auth + common-security + authorization-service
common-security → common-auth
authorization-service → standalone
common-auth → standalone
```

## 📁 **Folder Layout**

```
README.md
api-service/
    README.md
    src/main/java/com/example/apiservice/ApiController.java
authorization-service/
    README.md
    src/main/java/com/example/authorizationservice/AuthorizationService.java
common-auth/
    README.md
    src/main/java/com/example/commonauth/
        AuthService.java
        CustomAuthenticationProvider.java
        JwtAuthenticationFilter.java
        JwtTokenUtil.java
        TwoFactorAuthService.java
common-security/
    README.md
    src/main/java/com/example/commonsecurity/
        GrpcSecurityInterceptor.java
        SecurityConfig.java
        WebSocketSecurityInterceptor.java
graphql-service/
    README.md
    src/main/java/com/example/graphqlservice/
        GraphQLController.java
        GraphQLSecurityInterceptor.java
```

## 🧩 **Module Responsibilities**

- **api-service**: REST endpoints, integrates authentication and authorization
- **common-auth**: Authentication logic (session, JWT, 2FA)
- **common-security**: Security configuration, filters, interceptors
- **authorization-service**: Role and permission management
- **graphql-service**: Scaffold for future GraphQL API and security integration

## 🔗 **Authentication Methods & API Types**

- **Session-based**: CustomAuthenticationProvider, AuthService
- **JWT-based**: JwtAuthenticationFilter, JwtTokenUtil
- **LDAP**: LdapAuthenticationProvider (see authentication/ldap-auth.md)
- **OAuth2**: OAuth2 client (see authentication/oauth2-auth.md)
- **SSO**: SAML/OIDC integration (see authentication/sso-integration.md)
- **WebSocket**: WebSocketSecurityInterceptor (see common-security)
- **gRPC**: GrpcSecurityInterceptor (see common-security)
- **GraphQL**: GraphQLController, GraphQLSecurityInterceptor (see graphql-service)

## 🛡️ **Security Patterns**

- All authentication flows converge through SecurityConfig filter chain
- Role-based access via AuthorizationService
- JWT tokens include username and role claims
- SecurityContextHolder used for downstream authorization

## 🚀 **Next Steps**

- [Quick Setup →](quick-setup.md)
- [Authentication Methods →](../authentication/index.md)
- [API Reference →](../api/index.md)
- [Security Configuration →](../security/index.md)

---

**This modular structure demonstrates best practices for scalable, secure Spring applications and is designed for easy extension to WebSocket, gRPC, and GraphQL APIs as you continue learning.**