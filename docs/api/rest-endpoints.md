# REST Endpoints

Complete reference for all REST API endpoints in the Spring Security Reference project. Each endpoint demonstrates different authentication and authorization patterns.

## 🔓 **Public Endpoints**

### **GET /api/public/hello**
Public endpoint requiring no authentication.

=== "Request"
    ```http
    GET /api/public/hello
    Host: localhost:8080
    ```

=== "Response"
    ```json
    "Hello, world! (public endpoint - no authentication required)"
    ```

=== "cURL"
    ```bash
    curl http://localhost:8080/api/public/hello
    ```

**🎓 Learning Points:**
- No security constraints applied
- Accessible without any credentials  
- Used for health checks and public information

---

## 🔐 **Authentication Endpoints**

### **POST /api/auth/login**
Generate JWT token for API authentication.

=== "Request"
    ```http
    POST /api/auth/login
    Content-Type: application/x-www-form-urlencoded
    
    username=admin&password=password
    ```

=== "Response"
    ```json
    {
      "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJST0xFX0FETUlOIiwiaWF0IjoxNjk0NTIwMDAwLCJleHAiOjE2OTQ2MDY0MDB9.signature",
      "username": "admin", 
      "role": "ROLE_ADMIN",
      "message": "Login successful - use this JWT token for authenticated requests",
      "usage": "Add header: Authorization: Bearer eyJhbGciOiJIUzUxMiJ9..."
    }
    ```

=== "cURL"
    ```bash
    curl -X POST http://localhost:8080/api/auth/login \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=admin&password=password"
    ```

**🎓 Learning Points:**
- Generates JWT tokens with user identity and role claims
- No authentication required to obtain token
- Token expires after 24 hours (configurable)
- Role determination based on username pattern

**📝 Available Test Users:**
- `admin` / `password` → `ROLE_ADMIN`
- `user` / `password` → `ROLE_USER`
- `jdbcadmin` / `password` → `ROLE_ADMIN`
- `ldapadmin` / `password` → `ROLE_ADMIN`

### **GET /api/auth/info**
Retrieve current authentication information.

=== "Request"
    ```http
    GET /api/auth/info
    Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
    ```

=== "Response"
    ```json
    {
      "authenticated": true,
      "username": "admin",
      "authorities": [
        {
          "authority": "ROLE_ADMIN"
        }
      ],
      "authType": "JWT",
      "principalType": "UsernamePasswordAuthenticationToken"
    }
    ```

=== "cURL"
    ```bash
    curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
      http://localhost:8080/api/auth/info
    ```

**🎓 Learning Points:**
- Requires valid authentication
- Shows current security context details
- Identifies authentication method used
- Useful for debugging authentication issues

---

## 👨‍💼 **Admin Endpoints**

### **GET /api/admin/secure**
Secure endpoint requiring `ROLE_ADMIN` authority.

=== "Request"
    ```http
    GET /api/admin/secure
    Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
    ```

=== "Response"
    ```json
    {
      "message": "Hello, Admin! (secured endpoint)",
      "user": "admin",
      "authorities": [
        {
          "authority": "ROLE_ADMIN" 
        }
      ],
      "authType": "JWT"
    }
    ```

=== "cURL"
    ```bash
    curl -H "Authorization: Bearer YOUR_ADMIN_JWT_TOKEN" \
      http://localhost:8080/api/admin/secure
    ```

**🎓 Learning Points:**
- Requires `ROLE_ADMIN` authority
- Returns 403 Forbidden for non-admin users
- Supports all authentication methods (JWT, Basic, OAuth2)
- Demonstrates role-based access control

**⚠️ Error Response (403 Forbidden):**
```json
{
  "error": "Access Denied",
  "message": "You don't have permission to access this resource",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/admin/secure"
}
```

---

## 👤 **User Endpoints**

### **GET /api/user/secure**
Secure endpoint for users with `ROLE_USER` or `ROLE_ADMIN`.

=== "Request"
    ```http
    GET /api/user/secure  
    Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
    ```

=== "Response"
    ```json
    {
      "message": "Hello, User! (secured endpoint)",
      "user": "user",
      "authorities": [
        {
          "authority": "ROLE_USER"
        }
      ],
      "authType": "JWT"
    }
    ```

=== "cURL"
    ```bash
    curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
      http://localhost:8080/api/user/secure
    ```

**🎓 Learning Points:**
- Accepts both `ROLE_USER` and `ROLE_ADMIN`
- Demonstrates role hierarchy (ADMIN > USER)
- Multi-role endpoint access pattern
- Role-based response customization

---

## 🗄️ **JDBC Authentication Endpoints**

### **GET /api/jdbc/users**
Demonstration endpoint for JDBC database authentication.

=== "Request"
    ```http
    GET /api/jdbc/users
    Authorization: Basic amRiY2FkbWluOnBhc3N3b3Jk
    ```

=== "Response"
    ```json
    {
      "message": "JDBC Authentication Demo",
      "user": "jdbcadmin",
      "credentials": {
        "jdbcadmin": "password (ROLE_ADMIN)",
        "jdbcuser": "password (ROLE_USER)"
      }
    }
    ```

=== "cURL"
    ```bash
    # Using Basic Auth with JDBC credentials
    curl -H "Authorization: Basic amRiY2FkbWluOnBhc3N3b3Jk" \
      http://localhost:8080/api/jdbc/users
      
    # Or with username:password
    curl -u jdbcadmin:password \
      http://localhost:8080/api/jdbc/users
    ```

**🎓 Learning Points:**
- Demonstrates HTTP Basic authentication
- Uses database-stored user credentials
- Profile-specific endpoint (`jdbc` profile)
- Base64 encoded credentials in Authorization header

**📝 JDBC Test Credentials:**
- Username: `jdbcadmin`, Password: `password` (ROLE_ADMIN)
- Username: `jdbcuser`, Password: `password` (ROLE_USER)

---

## 🏢 **LDAP Authentication Endpoints**

### **GET /api/ldap/users**
Demonstration endpoint for LDAP directory authentication.

=== "Request"
    ```http
    GET /api/ldap/users
    Authorization: Basic bGRhcGFkbWluOnBhc3N3b3Jk
    ```

=== "Response"
    ```json
    {
      "message": "LDAP Authentication Demo",
      "user": "ldapadmin", 
      "credentials": {
        "ldapadmin": "password (ROLE_ADMIN)",
        "ldapuser": "password (ROLE_USER)"
      }
    }
    ```

=== "cURL"
    ```bash
    # Using Basic Auth with LDAP credentials
    curl -H "Authorization: Basic bGRhcGFkbWluOnBhc3N3b3Jk" \
      http://localhost:8080/api/ldap/users
      
    # Or with username:password  
    curl -u ldapadmin:password \
      http://localhost:8080/api/ldap/users
    ```

**🎓 Learning Points:**
- Demonstrates LDAP directory integration
- Uses embedded LDAP server for testing
- Profile-specific endpoint (`ldap` profile)
- Group-based role mapping

**📝 LDAP Test Credentials:**
- Username: `ldapadmin`, Password: `password` (ROLE_ADMIN)
- Username: `ldapuser`, Password: `password` (ROLE_USER)

---

## 🌐 **OAuth2 Authentication Endpoints**

### **GET /api/oauth2/profile**
User profile endpoint for OAuth2/OIDC authenticated users.

=== "OAuth2 User Request"
    ```http
    GET /api/oauth2/profile
    Cookie: JSESSIONID=ABC123...
    ```

=== "OAuth2 User Response"
    ```json
    {
      "message": "OAuth2 Authentication Demo",
      "user": "john.doe@example.com",
      "email": "john.doe@example.com",
      "provider": "OAuth2",
      "attributes": {
        "sub": "12345",
        "name": "John Doe", 
        "email": "john.doe@example.com",
        "picture": "https://avatar.url"
      }
    }
    ```

=== "Non-OAuth2 User Response"
    ```json
    {
      "message": "OAuth2 Authentication Demo",
      "user": "admin",
      "authorities": [
        {
          "authority": "ROLE_ADMIN"
        }
      ]
    }
    ```

=== "cURL"
    ```bash
    # After OAuth2 login, session cookie is used
    curl -H "Cookie: JSESSIONID=YOUR_SESSION_ID" \
      http://localhost:8080/api/oauth2/profile
    ```

**🎓 Learning Points:**
- Handles both OAuth2 and traditional users
- Extracts OAuth2 user attributes (email, name, picture)
- Session-based authentication post-OAuth2 flow
- Provider-specific attribute handling

**🔧 OAuth2 Configuration:**
- Supports Google, GitHub, Facebook providers
- OIDC (OpenID Connect) compatible
- Profile-specific endpoint (`oauth2` profile)

---

## 📊 **Endpoint Summary Matrix**

| Endpoint | Auth Method | Role Required | Profile | Purpose |
|----------|-------------|---------------|---------|----------|
| `/api/public/hello` | None | - | All | Public access demo |
| `/api/auth/login` | None | - | All | JWT token generation |
| `/api/auth/info` | Any | Any | All | Auth debugging |
| `/api/admin/secure` | Any | ADMIN | All | Admin-only access |
| `/api/user/secure` | Any | USER/ADMIN | All | User access demo |
| `/api/jdbc/users` | Basic Auth | Any | jdbc | JDBC auth demo |
| `/api/ldap/users` | Basic Auth | Any | ldap | LDAP auth demo |
| `/api/oauth2/profile` | Session/OAuth2 | Any | oauth2 | OAuth2 profile |

## 🎯 **Testing Strategies**

### **Unit Testing Endpoints**
```java
@Test
@WithMockUser(roles = "ADMIN")
void adminEndpointWithAdminRole() throws Exception {
    mockMvc.perform(get("/api/admin/secure"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Hello, Admin! (secured endpoint)"));
}
```

### **Integration Testing**
```java
@Test
void jwtAuthenticationFlow() {
    // 1. Login to get JWT token
    String token = getJwtToken("admin", "password");
    
    // 2. Use token to access secured endpoint
    given()
        .header("Authorization", "Bearer " + token)
        .when()
        .get("/api/admin/secure")
        .then()
        .statusCode(200);
}
```

## 🚀 **Next Steps**

- **[Authentication Flow →](auth-flow.md)** - Understand authentication sequences
- **[Error Handling →](error-handling.md)** - API error response patterns  
- **[Security Configuration →](../security/index.md)** - Security implementation details
- **[Testing Examples →](../examples/testing-api.md)** - Comprehensive testing patterns

---

**📋 This reference covers all REST endpoints with practical examples, authentication requirements, and educational insights for learning Spring Security patterns.**