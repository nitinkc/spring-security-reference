# Authentication Flow

Detailed authentication flow patterns and sequences for all supported authentication methods in the Spring Security Reference API.

## 🔄 **Authentication Architecture**

```mermaid
sequenceDiagram
    participant C as Client
    participant F as Security Filter
    participant P as Auth Provider
    participant S as Security Context
    participant A as API Controller
    
    C->>F: HTTP Request with Credentials
    F->>F: Extract Authentication Details
    F->>P: Authenticate Request
    P->>P: Validate Credentials
    P-->>F: Authentication Result
    F->>S: Set Security Context
    F->>A: Forward Request
    A->>A: Check Authorization
    A-->>C: JSON Response
```

## 🎯 **Authentication Method Flows**

### **1. JWT Token Authentication**

```mermaid
sequenceDiagram
    participant C as Client
    participant L as Login Endpoint
    participant J as JWT Util
    participant F as JWT Filter
    participant A as API Endpoint
    
    Note over C,A: Step 1: Obtain JWT Token
    C->>L: POST /api/auth/login<br/>username=admin&password=password
    L->>J: Generate JWT Token
    J->>J: Create Claims (username, role)
    J->>J: Sign with Secret Key
    J-->>L: JWT Token
    L-->>C: {"token": "eyJhbGci..."}
    
    Note over C,A: Step 2: Use JWT Token
    C->>F: GET /api/admin/secure<br/>Authorization: Bearer eyJhbGci...
    F->>F: Extract Token from Header
    F->>J: Validate JWT Token
    J->>J: Verify Signature & Expiry
    J-->>F: Claims {username, role}
    F->>F: Create Authentication Object
    F->>A: Forward Request
    A->>A: Check Role Authorization
    A-->>C: Secured Response
```

**🎓 JWT Flow Learning Points:**
- **Stateless Authentication**: No server-side session storage
- **Claims-Based**: User identity and roles encoded in token
- **Self-Contained**: Token includes all necessary information
- **Expiry Handling**: Tokens have built-in expiration

**📋 JWT Token Structure:**
```json
{
  "header": {
    "alg": "HS512",
    "typ": "JWT"
  },
  "payload": {
    "sub": "admin",
    "role": "ROLE_ADMIN", 
    "iat": 1694520000,
    "exp": 1694606400
  },
  "signature": "HMACSHA512(base64UrlEncode(header) + \".\" + base64UrlEncode(payload), secret)"
}
```

### **2. HTTP Basic Authentication**

```mermaid
sequenceDiagram
    participant C as Client
    participant F as Basic Auth Filter
    participant P as DaoAuthenticationProvider
    participant U as UserDetailsService
    participant A as API Endpoint
    
    C->>F: GET /api/jdbc/users<br/>Authorization: Basic dXNlcjpwYXNz
    F->>F: Decode Base64 Credentials
    F->>F: Extract Username & Password
    F->>P: Authenticate(username, password)
    P->>U: Load User Details
    U->>U: Query Database/LDAP
    U-->>P: UserDetails with Authorities
    P->>P: Verify Password
    P-->>F: Authentication Success
    F->>F: Set Security Context
    F->>A: Forward Request
    A-->>C: Secured Response
```

**🎓 Basic Auth Flow Learning Points:**
- **Request-Based**: Credentials sent with every request
- **Base64 Encoding**: Username:password encoded (not encrypted)
- **Database/LDAP Integration**: User details loaded from data source
- **Role Assignment**: Authorities loaded with user details

**📋 Basic Auth Header Format:**
```http
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
# Base64 encoded "username:password"
```

### **3. OAuth2 Authentication Flow**

```mermaid
sequenceDiagram
    participant C as Client/Browser
    participant A as Application
    participant P as OAuth2 Provider
    participant F as OAuth2 Filter
    participant E as API Endpoint
    
    Note over C,E: OAuth2 Authorization Code Flow
    C->>A: Access Protected Resource
    A-->>C: Redirect to OAuth2 Provider
    C->>P: Login & Grant Permission
    P-->>C: Redirect with Authorization Code
    C->>A: Authorization Code
    A->>P: Exchange Code for Access Token
    P-->>A: Access Token & ID Token
    A->>A: Create OAuth2User Principal
    A->>A: Set Security Context
    
    Note over C,E: Subsequent API Calls
    C->>F: GET /api/oauth2/profile<br/>Cookie: JSESSIONID=...
    F->>F: Load Authentication from Session
    F->>E: Forward Request
    E->>E: Extract OAuth2User Attributes
    E-->>C: Profile Response with OAuth2 Data
```

**🎓 OAuth2 Flow Learning Points:**
- **Authorization Code Flow**: Most secure OAuth2 flow
- **Provider Integration**: Google, GitHub, Facebook support
- **Session-Based**: Post-authentication uses session cookies
- **Attribute Mapping**: Provider-specific user attributes

### **4. Session-Based Authentication**

```mermaid
sequenceDiagram
    participant C as Client
    participant L as Login Form
    participant P as Auth Provider
    participant S as Session Manager
    participant F as Session Filter
    participant A as API Endpoint
    
    Note over C,A: Initial Login
    C->>L: POST /login (username, password)
    L->>P: Authenticate Credentials
    P-->>L: Authentication Success
    L->>S: Create HTTP Session
    S-->>C: Set-Cookie: JSESSIONID=ABC123
    
    Note over C,A: Subsequent Requests
    C->>F: GET /api/user/secure<br/>Cookie: JSESSIONID=ABC123
    F->>S: Retrieve Authentication from Session
    S-->>F: Authentication Object
    F->>A: Forward Request with Authentication
    A-->>C: Secured Response
```

**🎓 Session Flow Learning Points:**
- **Server-Side State**: Authentication stored in server session
- **Cookie-Based**: Session ID transmitted via HTTP cookies
- **CSRF Protection**: Cross-Site Request Forgery mitigation
- **Session Lifecycle**: Login, timeout, logout management

## 🔍 **Authentication Method Detection**

The API automatically detects and reports the authentication method used:

```java
public String determineAuthType(Authentication auth) {
    String principalType = auth.getPrincipal().getClass().getSimpleName();
    
    if (principalType.contains("OAuth2")) {
        return "OAuth2";
    } else if (principalType.contains("Ldap")) {
        return "LDAP";
    } else if (principalType.contains("User")) {
        return "JDBC/Database";
    } else if (auth.getDetails().toString().contains("JWT")) {
        return "JWT";
    } else {
        return "Custom/Session";
    }
}
```

## 🛡️ **Security Filter Chain Order**

```mermaid
graph TD
    A[HTTP Request] --> B[CSRF Filter]
    B --> C[Logout Filter]
    C --> D[OAuth2 Authorization Filter]
    D --> E[OAuth2 Login Filter]
    E --> F[JWT Authentication Filter]
    F --> G[Basic Authentication Filter]
    G --> H[Form Login Filter]
    H --> I[Session Management Filter]
    I --> J[Authorization Filter]
    J --> K[Controller]
    
    style A fill:#e1f5fe
    style F fill:#c8e6c9
    style G fill:#c8e6c9
    style J fill:#ffecb3
    style K fill:#fff3e0
```

**🎓 Filter Chain Learning Points:**
- **Order Matters**: Filters execute in specific sequence
- **First Match Wins**: First successful authentication is used
- **Skip Logic**: Authenticated requests skip unnecessary filters
- **Exception Handling**: Authentication failures handled gracefully

## 🔐 **Authorization Decision Flow**

```mermaid
flowchart TD
    A[Authenticated Request] --> B{URL Pattern Match}
    
    B -->|/api/public/**| C[✅ Allow - Public Access]
    B -->|/api/admin/**| D{Has ROLE_ADMIN?}
    B -->|/api/user/**| E{Has ROLE_USER or ROLE_ADMIN?}
    B -->|Other patterns| F{Authenticated?}
    
    D -->|Yes| G[✅ Allow - Admin Access]
    D -->|No| H[❌ 403 Access Denied]
    
    E -->|Yes| I[✅ Allow - User Access]  
    E -->|No| H
    
    F -->|Yes| J[✅ Allow - Authenticated Access]
    F -->|No| K[❌ 401 Unauthorized]
    
    style C fill:#c8e6c9
    style G fill:#c8e6c9
    style I fill:#c8e6c9
    style J fill:#c8e6c9
    style H fill:#ffcdd2
    style K fill:#ffcdd2
```

## 📱 **Multi-Profile Authentication**

Different Spring profiles enable different authentication methods:

=== "Default Profile"
    ```yaml
    # Supports all authentication methods
    spring:
      profiles:
        active: default
    ```
    **Available Methods:** JWT, Basic Auth, OAuth2, Session

=== "JWT Profile" 
    ```yaml
    spring:
      profiles:
        active: jwt
    ```
    **Primary Method:** JWT Token Authentication

=== "JDBC Profile"
    ```yaml
    spring:
      profiles:
        active: jdbc  
    ```
    **Primary Method:** Database-backed Basic Authentication

=== "LDAP Profile"
    ```yaml
    spring:
      profiles:
        active: ldap
    ```
    **Primary Method:** LDAP Directory Authentication

=== "OAuth2 Profile"
    ```yaml
    spring:
      profiles:
        active: oauth2
    ```
    **Primary Method:** OAuth2/OIDC Authentication

## 🧪 **Testing Authentication Flows**

### **JWT Flow Test**
```java
@Test
void jwtAuthenticationFlow() {
    // Step 1: Get JWT token
    ResponseEntity<Map> loginResponse = restTemplate.postForEntity(
        "/api/auth/login",
        createLoginRequest("admin", "password"),
        Map.class
    );
    
    String token = (String) loginResponse.getBody().get("token");
    
    // Step 2: Use JWT token
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    
    ResponseEntity<Map> response = restTemplate.exchange(
        "/api/admin/secure",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        Map.class
    );
    
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
}
```

### **Basic Auth Flow Test**
```java
@Test
void basicAuthenticationFlow() {
    HttpHeaders headers = new HttpHeaders();
    headers.setBasicAuth("jdbcadmin", "password");
    
    ResponseEntity<Map> response = restTemplate.exchange(
        "/api/jdbc/users",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        Map.class
    );
    
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
}
```

## ⚡ **Performance Considerations**

### **Authentication Method Performance**

| Method | Setup Cost | Request Cost | Scalability | Use Case |
|--------|------------|--------------|-------------|----------|
| **JWT** | Low | Very Low | Excellent | Stateless APIs |
| **Basic Auth** | Low | Medium | Good | Simple APIs |
| **OAuth2** | High | Low | Excellent | External identity |
| **Session** | Medium | Low | Fair | Traditional web apps |

### **Optimization Tips**
- **JWT**: Use short expiry times with refresh tokens
- **Basic Auth**: Consider caching user details
- **OAuth2**: Implement token refresh logic
- **Session**: Configure appropriate session timeout

## 🚀 **Next Steps**

- **[Error Handling →](error-handling.md)** - Authentication and authorization error patterns
- **[REST Endpoints →](rest-endpoints.md)** - Complete endpoint reference
- **[Security Configuration →](../security/index.md)** - Deep dive into security setup
- **[Testing Examples →](../examples/testing-auth.md)** - Comprehensive testing patterns

---

**🔄 Understanding authentication flows is crucial for implementing secure APIs. Each method has specific use cases, benefits, and implementation patterns that suit different architectural requirements.**