# API Reference

Comprehensive REST API documentation for the Spring Security Reference project. This section covers all available endpoints, authentication flows, and integration patterns.

## 🌐 **API Architecture Overview**

```mermaid
graph TD
    A[Client Request] --> B{Authentication Required?}
    B -->|No| C[Public Endpoints]
    B -->|Yes| D[Authentication Check]
    
    D --> E{Auth Method}
    E -->|JWT Token| F[JWT Filter]
    E -->|Basic Auth| G[HTTP Basic]
    E -->|OAuth2| H[OAuth2 Filter]
    E -->|Session| I[Session Auth]
    
    F --> J[Authorization Check]
    G --> J
    H --> J
    I --> J
    
    J --> K{Role/Permission Check}
    K -->|✅ Authorized| L[Controller Handler]
    K -->|❌ Forbidden| M[403 Access Denied]
    
    C --> L
    L --> N[Business Logic]
    N --> O[JSON Response]
    
    D -->|❌ Invalid| P[401 Unauthorized]
    
    style A fill:#e1f5fe
    style F fill:#c8e6c9
    style G fill:#c8e6c9
    style H fill:#c8e6c9
    style I fill:#c8e6c9
    style L fill:#fff3e0
    style O fill:#e8f5e8
```

## 📊 **API Categories**

### **🔓 Public Endpoints**
No authentication required - accessible to all clients.

### **🔐 Authenticated Endpoints** 
Require valid authentication tokens or credentials.

### **👥 Role-Based Endpoints**
Require specific roles (`ROLE_ADMIN`, `ROLE_USER`) for access.

### **🎯 Method-Specific Endpoints**
Demonstrate different authentication methods (JWT, JDBC, LDAP, OAuth2).

## 🎯 **Quick Start**

### **1. Start the Application**
```bash
# Run with default profile (supports all auth methods)
./gradlew :rest-api:bootRun

# Or run with a specific profile
./gradlew :rest-api:bootRun --args='--spring.profiles.active=jwt'
```

### **2. Test Public Endpoint**
```bash
curl http://localhost:8080/api/public/hello
```

### **3. Get JWT Token**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=password"
```

### **4. Access Protected Endpoint**
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/admin/secure
```

## 📋 **Available Endpoints**

| Category | Endpoint | Method | Auth Required | Role Required |
|----------|----------|--------|---------------|---------------|
| **Public** | `/api/public/hello` | GET | ❌ | - |
| **Auth** | `/api/auth/login` | POST | ❌ | - |
| **Auth** | `/api/auth/info` | GET | ✅ | Any |
| **Admin** | `/api/admin/secure` | GET | ✅ | `ROLE_ADMIN` |
| **User** | `/api/user/secure` | GET | ✅ | `ROLE_USER`, `ROLE_ADMIN` |
| **JDBC** | `/api/jdbc/users` | GET | ✅ | Any (Basic Auth) |
| **LDAP** | `/api/ldap/users` | GET | ✅ | Any (Basic Auth) |
| **OAuth2** | `/api/oauth2/profile` | GET | ✅ | OAuth2 User |

## 🔐 **Authentication Methods**

### **JWT Token Authentication**
```http
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

### **HTTP Basic Authentication** 
```http
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

### **OAuth2 Authentication**
Redirect-based OAuth2 flow with provider integration.

### **Session-Based Authentication**
Traditional session cookies with CSRF protection.

## 🎓 **Learning Path**

### **Beginner**
1. **[REST Endpoints →](rest-endpoints.md)** - Explore all available API endpoints
2. **[Authentication Flow →](auth-flow.md)** - Understand authentication patterns
3. **[Error Handling →](error-handling.md)** - Learn about API error responses

### **Advanced**
- **[Security Configuration →](../security/index.md)** - Deep dive into security setup
- **[Authentication Methods →](../authentication/index.md)** - Multiple auth strategies
- **[Testing →](../examples/testing-api.md)** - API testing patterns

## 🛠️ **Development Tools**

### **Postman Collection**
```bash
# Import the provided collection
Spring-Security-Reference-APIs-Enhanced.postman_collection.json
```

### **VS Code REST Client**
```bash
# Use the provided .http file
api-testing.http
```

### **cURL Examples** 
Every endpoint includes ready-to-use cURL commands.

## 🚀 **Next Steps**

- **[REST Endpoints →](rest-endpoints.md)** - Complete endpoint reference
- **[Authentication Flow →](auth-flow.md)** - Authentication sequence diagrams  
- **[Error Handling →](error-handling.md)** - Error response patterns
- **[Security Configuration →](../security/index.md)** - Security implementation details

---

**🌐 The API Reference provides complete documentation for integrating with our Spring Security demonstration endpoints. Each section includes practical examples and educational insights.**