# Project Structure

This page explains the modular architecture and folder structure of the Spring Security Reference project.

## 🏗️ **Overview**

The project uses a layered modular architecture for clear separation of concerns:

```
rest-api → common-auth + common-security + authorization-service + jdbc-auth + ldap-auth + oauth2-auth
common-security → common-auth
authorization-service → standalone
common-auth → standalone
jdbc-auth → standalone
ldap-auth → standalone
oauth2-auth → standalone
```

## 📁 **Folder Layout**

```
README.md
rest-api/
    pom.xml
    src/main/java/com/example/spring/security/reference/api/
        RestApiApplication.java
        ApiController.java
authorization-service/
    pom.xml
    src/main/java/com/example/spring/security/reference/authorizationservice/
        AuthorizationService.java
common-auth/
    pom.xml
    src/main/java/com/example/spring/security/reference/commonauth/
        AuthService.java
        CustomAuthenticationProvider.java
        JwtAuthenticationFilter.java
        JwtTokenUtil.java
        TwoFactorAuthService.java
common-security/
    pom.xml
    src/main/java/com/example/spring/security/reference/commonsecurity/
        GrpcSecurityInterceptor.java
        MultiAuthSecurityConfig.java
        SecurityConfig.java
        WebSocketSecurityInterceptor.java
jdbc-auth/
    pom.xml
    src/main/java/com/example/spring/security/reference/jdbcauth/
        JdbcAuthConfig.java
        JdbcDataInitializer.java
ldap-auth/
    pom.xml
    src/main/java/com/example/spring/security/reference/ldapauth/
        LdapAuthConfig.java
        PersonContextMapper.java
oauth2-auth/
    pom.xml
    src/main/java/com/example/spring/security/reference/oauth2auth/
        OAuth2AuthConfig.java
        OAuth2AuthenticationSuccessHandler.java
graphql-service/
    pom.xml
    src/main/java/com/example/spring/security/reference/graphqlservice/
        GraphQLController.java
        GraphQLSecurityInterceptor.java
websocket-service/
    pom.xml
    src/main/java/com/example/spring/security/reference/websocketservice/
        WebSocketConfig.java
        WebSocketController.java
        WebSocketSecurityInterceptor.java
```

## 🧩 **Module Responsibilities**

| Module | Purpose |
|--------|---------|
| **rest-api** | Main application entry point, REST endpoints, integrates all authentication modules |
| **common-auth** | Core authentication logic (session-based, JWT, 2FA hooks) |
| **common-security** | Security configuration, filter chains, protocol interceptors |
| **authorization-service** | Role and permission management |
| **jdbc-auth** | Database-backed user authentication with H2 and BCrypt |
| **ldap-auth** | LDAP/Active Directory authentication |
| **oauth2-auth** | OAuth2/OpenID Connect social login integration |
| **graphql-service** | GraphQL API with security integration (scaffold) |
| **websocket-service** | WebSocket messaging with security |

## 🔗 **Authentication Methods & API Types**

### Authentication Providers
- **Session-based**: `CustomAuthenticationProvider` + `AuthService.authenticateSession()`
- **JWT-based**: `JwtAuthenticationFilter` + `JwtTokenUtil`
- **JDBC**: `JdbcAuthConfig` with `DaoAuthenticationProvider` and `JdbcUserDetailsManager`
- **LDAP**: `LdapAuthConfig` with embedded LDAP server
- **OAuth2**: `OAuth2AuthConfig` for social login (GitHub, Google, etc.)

### Protocol Security
- **REST**: Configured via `MultiAuthSecurityConfig` filter chain
- **WebSocket**: `WebSocketSecurityInterceptor` in `ChannelInterceptor.preSend()`
- **gRPC**: `GrpcSecurityInterceptor` as `ServerInterceptor`
- **GraphQL**: `GraphQLSecurityInterceptor` (scaffold)

## 🛡️ **Security Patterns**

- All authentication flows converge through `MultiAuthSecurityConfig` filter chain
- Role-based access via `AuthorizationService.getUserRole()` and `hasPermission()`
- JWT tokens include `username` (subject) and `role` claims
- `SecurityContextHolder` used for downstream authorization
- JWT filter runs **before** `UsernamePasswordAuthenticationFilter` in the chain

## 📦 **Package Naming Convention**

All modules follow the base package: `com.example.spring.security.reference`

| Module | Package |
|--------|---------|
| rest-api | `...reference.api` |
| common-auth | `...reference.commonauth` |
| common-security | `...reference.commonsecurity` |
| authorization-service | `...reference.authorizationservice` |
| jdbc-auth | `...reference.jdbcauth` |
| ldap-auth | `...reference.ldapauth` |
| oauth2-auth | `...reference.oauth2auth` |
| graphql-service | `...reference.graphqlservice` |
| websocket-service | `...reference.websocketservice` |

## 🚀 **Next Steps**

- [Quick Setup →](quick-setup.md)
- [Authentication Methods →](../authentication/index.md)
- [API Reference →](../api/index.md)
- [Security Configuration →](../security/index.md)

---

**This modular structure demonstrates best practices for scalable, secure Spring applications and is designed for easy extension to WebSocket, gRPC, and GraphQL APIs as you continue learning.**