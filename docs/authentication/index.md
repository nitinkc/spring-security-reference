# Authentication Methods

This section covers authentication methods implemented or planned in the Spring Security Reference Project. Check the [Coverage Registry](../coverage.md) before treating documentation as runnable proof.

## 🎯 Overview

The project tracks these authentication and federation strategies:

| Method | Module | Use Case | Complexity |
|--------|--------|----------|------------|
| **[JDBC Authentication](jdbc-auth.md)** | `jdbc-auth` | Database-backed users | ⭐⭐ |
| **[LDAP Authentication](ldap-auth.md)** | `ldap-auth` | Enterprise directories | ⭐⭐⭐ |
| **[OAuth2 Authentication](oauth2-auth.md)** | `oauth2-auth` scaffold | OAuth2/OIDC login and API security | ⭐⭐⭐⭐ |
| **[SSO with OIDC and SAML](sso-integration.md)** | Planned labs | Cross-application enterprise federation | ⭐⭐⭐⭐⭐ |
| **[JWT Tokens](jwt-tokens.md)** | `common-auth` | Stateless API auth | ⭐⭐⭐ |

## 🏗️ Authentication Architecture

```mermaid
graph TD
    A[HTTP Request] --> B{Authentication Required?}
    B -->|No| C[Public Endpoint]
    B -->|Yes| D[Security Filter Chain]
    
    D --> E{Auth Method}
    E -->|JWT Token| F[JWT Filter]
    E -->|Form Login| G[Login Form]
    E -->|Basic Auth| H[Basic Auth Filter]
    
    F --> I[JWT Provider]
    G --> J{Provider Type}
    H --> J
    
    J -->|JDBC| K[JDBC Provider]
    J -->|LDAP| L[LDAP Provider]  
    J -->|OAuth2| M[OAuth2 Provider]
    
    K --> N[Database]
    L --> O[LDAP Directory]
    M --> P[Identity Provider]
    
    I --> Q[Security Context]
    K --> Q
    L --> Q
    M --> Q
    
    Q --> R[Authorized Request]
```

## 🔄 Authentication Flow

### Standard Flow

Every authentication method follows the same basic pattern:

1. **Request Intercepted**: Security filters examine incoming requests
2. **Credentials Extracted**: Username/password, token, or OAuth2 code
3. **Provider Selection**: Choose appropriate authentication provider
4. **Validation**: Verify credentials against user store
5. **Authorization**: Load user roles and permissions
6. **Security Context**: Set authenticated user in context
7. **Request Processing**: Continue to protected resource

### Flow Variations

Each authentication method has unique characteristics:

#### Database (JDBC) Flow
```mermaid
sequenceDiagram
    participant U as User
    participant F as JWT Filter
    participant P as JDBC Provider
    participant D as Database
    
    U->>F: POST /api/auth/login
    F->>P: Authenticate(username, password)
    P->>D: SELECT user WHERE username=?
    D-->>P: User record
    P->>P: Verify BCrypt password
    P-->>F: Authentication success
    F-->>U: JWT Token
```

#### Directory (LDAP) Flow
```mermaid
sequenceDiagram
    participant U as User
    participant F as Form Filter
    participant P as LDAP Provider
    participant L as LDAP Server
    
    U->>F: Form Login
    F->>P: Authenticate(username, password)
    P->>L: Search user in directory
    L-->>P: User DN
    P->>L: Bind with user credentials
    L-->>P: Bind successful
    P->>L: Get user groups
    L-->>P: Group memberships
    P-->>F: Authentication + Authorities
    F-->>U: Redirect to secured page
```

#### OAuth2 Flow
```mermaid
sequenceDiagram
    participant U as User
    participant A as Application
    participant P as OAuth2 Provider
    
    U->>A: Click "Login with Google"
    A->>P: Redirect to authorization URL
    P->>U: Present consent screen
    U->>P: Approve application
    P->>A: Redirect with authorization code
    A->>P: Exchange code for tokens
    P-->>A: Access token + ID token
    A->>P: Get user profile
    P-->>A: User information
    A-->>U: Authenticated session
```

## 🔧 Configuration Patterns

### Multiple Authentication Providers

The project demonstrates how to combine multiple authentication methods:

```java
@Configuration
public class SecurityConfig {
    
    @Bean
    public AuthenticationManager authenticationManager(
            JdbcAuthenticationProvider jdbcProvider,
            LdapAuthenticationProvider ldapProvider) {
        
        return new ProviderManager(
            Arrays.asList(jdbcProvider, ldapProvider)
        );
    }
}
```

### Profile-Based Configuration

Different authentication methods can be enabled using Spring profiles:

```yaml
# application-jdbc.yml
spring:
  profiles:
    include: jdbc-only
  
# application-ldap.yml  
spring:
  profiles:
    include: ldap-only
```

## 🎓 Learning Path

### Beginner Path
1. **[JDBC Authentication](jdbc-auth.md)** - Start with database auth
2. **[JWT Tokens](jwt-tokens.md)** - Learn stateless authentication
3. **[API Testing](../examples/testing-auth.md)** - Practice with endpoints

### Intermediate Path
1. **[LDAP Authentication](ldap-auth.md)** - Enterprise directory integration
2. **[Security Configuration](../security/index.md)** - Advanced security setup
3. **[Custom Providers](../examples/custom-providers.md)** - Build custom auth

### Advanced Path
1. **[OAuth2 Authentication](oauth2-auth.md)** - OAuth2 client and resource-server concepts
2. **[SSO with OIDC and SAML](sso-integration.md)** - Federation, sessions, logout, and assertion security
3. **[SSO and SAML Labs](../labs.md#track-c-sso-and-saml-20)** - Build executable proof
4. **[Advanced Patterns](../examples/advanced-patterns.md)** - Delegation and workload identity
5. **[Production Setup](../deployment/production.md)** - Deploy securely

## 🔍 Comparison Matrix

| Feature | JDBC | LDAP | OAuth2 | JWT |
|---------|------|------|--------|-----|
| **User Storage** | Database | Directory | External Provider | Stateless |
| **Password Management** | Application | Directory | Provider | N/A |
| **Enterprise Integration** | Medium | High | High | High |
| **Scalability** | High | High | Very High | Very High |
| **Setup Complexity** | Low | Medium | High | Low |
| **Offline Capability** | Yes | No | No | Yes |
| **Social Login** | No | No | Yes | N/A |
| **Session State** | Stateful | Stateful | Stateful | Stateless |

## 🔨 Implementation Tips

### Choosing the Right Method

- **JDBC**: Internal applications with custom user management
- **LDAP**: Enterprise environments with existing directories
- **OIDC SSO**: Preferred federation for new browser and mobile applications
- **SAML SSO**: Established enterprise workforce and partner federation
- **OAuth2 access tokens**: Delegated API authorization
- **JWT**: A token format, not an authentication or SSO protocol by itself

### Best Practices

1. **Security First**: Always use HTTPS in production
2. **Password Policies**: Implement strong password requirements
3. **Token Expiry**: Set appropriate token lifetimes
4. **Logging**: Monitor authentication attempts
5. **Error Handling**: Don't leak sensitive information

### Common Pitfalls

- **Password Storage**: Never store plain text passwords
- **Token Security**: Protect JWT signing keys
- **Session Management**: Consider session fixation attacks
- **Rate Limiting**: Prevent brute force attacks

## 🔗 Next Steps

Ready to dive deeper? Explore specific authentication methods:

- **[JDBC Authentication →](jdbc-auth.md)** Database-backed authentication
- **[LDAP Authentication →](ldap-auth.md)** Directory service integration
- **[OAuth2 Authentication →](oauth2-auth.md)** Modern identity protocols
- **[JWT Tokens →](jwt-tokens.md)** Stateless token authentication

Or explore related topics:

- **[Security Configuration →](../security/index.md)** Learn security setup patterns
- **[API Reference →](../api/index.md)** Test endpoints and flows
- **[Examples & Tutorials →](../examples/index.md)** Practice with real scenarios