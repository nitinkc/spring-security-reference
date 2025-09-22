# Error Handling

Comprehensive guide to API error responses, HTTP status codes, and error handling patterns in the Spring Security Reference project.

## 🚨 **Error Response Architecture**

```mermaid
flowchart TD
    A[API Request] --> B{Authentication Valid?}
    B -->|No| C[401 Unauthorized]
    B -->|Yes| D{Authorization Check}
    
    D -->|Forbidden| E[403 Access Denied]
    D -->|Allowed| F{Request Valid?}
    
    F -->|Invalid| G[400 Bad Request]
    F -->|Valid| H[Controller Processing]
    
    H --> I{Business Logic}
    I -->|Error| J[500 Internal Server Error]
    I -->|Success| K[200/201/204 Success]
    
    C --> L[Error Response JSON]
    E --> L
    G --> L
    J --> L
    
    style C fill:#ffcdd2
    style E fill:#ffcdd2
    style G fill:#ffcdd2
    style J fill:#ffcdd2
    style K fill:#c8e6c9
    style L fill:#fff3e0
```

## 📊 **HTTP Status Code Reference**

### **🟢 Success Responses (2xx)**

| Status Code | Endpoint Example | Description |
|-------------|------------------|-------------|
| **200 OK** | `GET /api/user/secure` | Successful GET request |
| **201 Created** | `POST /api/users` | Resource created successfully |
| **204 No Content** | `DELETE /api/users/123` | Successful deletion |

### **🔴 Client Error Responses (4xx)**

| Status Code | Scenario | Description |
|-------------|----------|-------------|
| **400 Bad Request** | Invalid request parameters | Malformed request data |
| **401 Unauthorized** | Missing/invalid authentication | Authentication required |
| **403 Forbidden** | Insufficient permissions | Authorization denied |
| **404 Not Found** | Endpoint doesn't exist | Resource not found |
| **405 Method Not Allowed** | Wrong HTTP method | Method not supported |

### **🟡 Server Error Responses (5xx)**

| Status Code | Scenario | Description |
|-------------|----------|-------------|
| **500 Internal Server Error** | Unhandled exception | Server-side error |
| **503 Service Unavailable** | Service temporarily down | Maintenance mode |

## 🔐 **Authentication Error Responses**

### **401 Unauthorized - Missing Authentication**

=== "Scenario"
    ```http
    GET /api/admin/secure
    # No Authorization header
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 401,
      "error": "Unauthorized",
      "message": "Authentication required",
      "path": "/api/admin/secure"
    }
    ```

=== "Headers"
    ```http
    HTTP/1.1 401 Unauthorized
    Content-Type: application/json
    WWW-Authenticate: Bearer realm="API"
    ```

**🎓 Learning Points:**
- No valid authentication credentials provided
- Client must authenticate before accessing resource
- `WWW-Authenticate` header suggests authentication method

### **401 Unauthorized - Invalid JWT Token**

=== "Scenario"
    ```http
    GET /api/admin/secure
    Authorization: Bearer invalid_token_here
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 401,
      "error": "Unauthorized",
      "message": "Invalid or expired JWT token",
      "details": {
        "tokenError": "JWT signature does not match locally computed signature",
        "tokenStatus": "INVALID_SIGNATURE"
      },
      "path": "/api/admin/secure"
    }
    ```

**🎓 JWT Token Error Types:**
- **Invalid Signature**: Token tampered or wrong secret key
- **Expired Token**: Token past expiration time
- **Malformed Token**: Invalid JWT structure
- **Missing Claims**: Required claims not present

### **401 Unauthorized - Expired JWT Token**

=== "Scenario"
    ```http
    GET /api/user/secure
    Authorization: Bearer eyJhbGci...expired_token
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 401,
      "error": "Unauthorized",
      "message": "JWT token has expired",
      "details": {
        "tokenError": "JWT expired at 2024-01-15T09:30:00Z",
        "tokenStatus": "EXPIRED",
        "expiredAt": "2024-01-15T09:30:00Z",
        "currentTime": "2024-01-15T10:30:00Z"
      },
      "path": "/api/user/secure"
    }
    ```

**🔄 Token Refresh Recommendation:**
```json
{
  "error": "Token expired",
  "recommendation": "Please obtain a new token via POST /api/auth/login",
  "refreshEndpoint": "/api/auth/login"
}
```

### **401 Unauthorized - Invalid Basic Auth**

=== "Scenario"
    ```http
    GET /api/jdbc/users
    Authorization: Basic aW52YWxpZDppbnZhbGlk
    # Base64: "invalid:invalid"
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 401,
      "error": "Unauthorized",
      "message": "Invalid username or password",
      "details": {
        "authType": "Basic Authentication",
        "reason": "Bad credentials"
      },
      "path": "/api/jdbc/users"
    }
    ```

## 🚫 **Authorization Error Responses**

### **403 Forbidden - Insufficient Role**

=== "Scenario"
    ```http
    GET /api/admin/secure
    Authorization: Bearer valid_user_token_with_ROLE_USER
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 403,
      "error": "Access Denied",
      "message": "You don't have permission to access this resource",
      "details": {
        "requiredRole": "ROLE_ADMIN",
        "userRoles": ["ROLE_USER"],
        "resource": "/api/admin/secure",
        "action": "GET"
      },
      "path": "/api/admin/secure"
    }
    ```

**🎓 Learning Points:**
- User is authenticated but lacks required permissions
- Shows required vs. actual roles for debugging
- Different from 401 - authentication was successful

### **403 Forbidden - Method Security**

=== "Scenario"
    ```java
    @PreAuthorize("hasRole('ADMIN') and hasPermission(#userId, 'User', 'DELETE')")
    @DeleteMapping("/api/users/{userId}")
    public void deleteUser(@PathVariable String userId) {
        // Method execution
    }
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 403,
      "error": "Access Denied",
      "message": "Method access denied",
      "details": {
        "methodSecurity": true,
        "expression": "hasRole('ADMIN') and hasPermission(#userId, 'User', 'DELETE')",
        "evaluationResult": false,
        "failedCondition": "hasPermission(#userId, 'User', 'DELETE')"
      },
      "path": "/api/users/123"
    }
    ```

## ❌ **Request Error Responses**

### **400 Bad Request - Invalid Parameters**

=== "Scenario"
    ```http
    POST /api/auth/login
    Content-Type: application/x-www-form-urlencoded
    
    username=&password=
    # Empty username and password
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 400,
      "error": "Bad Request",
      "message": "Validation failed for request parameters",
      "details": {
        "validationErrors": [
          {
            "field": "username",
            "message": "Username is required and cannot be empty",
            "rejectedValue": ""
          },
          {
            "field": "password", 
            "message": "Password is required and cannot be empty",
            "rejectedValue": ""
          }
        ]
      },
      "path": "/api/auth/login"
    }
    ```

### **404 Not Found - Endpoint Not Exist**

=== "Scenario"
    ```http
    GET /api/nonexistent/endpoint
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 404,
      "error": "Not Found",
      "message": "No endpoint found for GET /api/nonexistent/endpoint",
      "path": "/api/nonexistent/endpoint"
    }
    ```

### **405 Method Not Allowed**

=== "Scenario"
    ```http
    PUT /api/public/hello
    # Endpoint only supports GET
    ```

=== "Response"
    ```json
    {
      "timestamp": "2024-01-15T10:30:00.123Z",
      "status": 405,
      "error": "Method Not Allowed",
      "message": "Request method 'PUT' not supported",
      "details": {
        "requestMethod": "PUT",
        "supportedMethods": ["GET"]
      },
      "path": "/api/public/hello"
    }
    ```

## 🔧 **Custom Error Handler Implementation**

### **Global Exception Handler**

```java
@RestControllerAdvice
public class ApiExceptionHandler {
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest request) {
            
        ErrorResponse error = ErrorResponse.builder()
            .timestamp(Instant.now())
            .status(HttpStatus.FORBIDDEN.value())
            .error("Access Denied")
            .message("You don't have permission to access this resource")
            .path(request.getRequestURI())
            .build();
            
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }
    
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex, HttpServletRequest request) {
            
        ErrorResponse error = ErrorResponse.builder()
            .timestamp(Instant.now())
            .status(HttpStatus.UNAUTHORIZED.value())
            .error("Unauthorized")
            .message("Authentication required")
            .path(request.getRequestURI())
            .build();
            
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }
}
```

### **Custom Access Denied Handler**

```java
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        
        ErrorResponse error = ErrorResponse.builder()
            .timestamp(Instant.now())
            .status(403)
            .error("Access Denied")
            .message("You don't have permission to access this resource")
            .path(request.getRequestURI())
            .details(Map.of(
                "user", request.getRemoteUser(),
                "requiredAuthority", extractRequiredAuthority(request),
                "userAuthorities", getCurrentUserAuthorities()
            ))
            .build();
            
        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(error));
    }
}
```

## 📱 **Client Error Handling Strategies**

### **JavaScript/TypeScript Client**

```javascript
const apiClient = {
    async request(url, options = {}) {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getJwtToken()}`,
                ...options.headers
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new ApiError(errorData);
        }
        
        return response.json();
    }
};

class ApiError extends Error {
    constructor(errorResponse) {
        super(errorResponse.message);
        this.status = errorResponse.status;
        this.error = errorResponse.error;
        this.details = errorResponse.details;
        this.path = errorResponse.path;
        this.timestamp = errorResponse.timestamp;
    }
    
    isAuthenticationError() {
        return this.status === 401;
    }
    
    isAuthorizationError() {
        return this.status === 403;
    }
    
    isTokenExpiredError() {
        return this.status === 401 && 
               this.details?.tokenStatus === 'EXPIRED';
    }
}

// Usage example
try {
    const userData = await apiClient.request('/api/admin/secure');
    console.log('User data:', userData);
} catch (error) {
    if (error instanceof ApiError) {
        if (error.isTokenExpiredError()) {
            // Refresh token and retry
            await refreshAuthToken();
            return apiClient.request('/api/admin/secure');
        } else if (error.isAuthenticationError()) {
            // Redirect to login
            redirectToLogin();
        } else if (error.isAuthorizationError()) {
            // Show access denied message
            showAccessDeniedMessage();
        }
    }
}
```

### **Java Client (RestTemplate)**

```java
@Service
public class ApiClient {
    
    private final RestTemplate restTemplate;
    
    public ApiClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        
        // Configure error handling
        restTemplate.setErrorHandler(new CustomResponseErrorHandler());
    }
    
    public <T> T makeRequest(String url, Class<T> responseType) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(getJwtToken());
            HttpEntity<?> entity = new HttpEntity<>(headers);
            
            ResponseEntity<T> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, responseType);
                
            return response.getBody();
            
        } catch (HttpClientErrorException ex) {
            handleClientError(ex);
            throw ex;
        } catch (HttpServerErrorException ex) {
            handleServerError(ex);
            throw ex;
        }
    }
    
    private void handleClientError(HttpClientErrorException ex) {
        if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            // Handle authentication error
            log.warn("Authentication failed: {}", ex.getResponseBodyAsString());
        } else if (ex.getStatusCode() == HttpStatus.FORBIDDEN) {
            // Handle authorization error
            log.warn("Access denied: {}", ex.getResponseBodyAsString());
        }
    }
}

static class CustomResponseErrorHandler implements ResponseErrorHandler {
    
    @Override
    public boolean hasError(ClientHttpResponse response) throws IOException {
        return response.getStatusCode().is4xxClientError() || 
               response.getStatusCode().is5xxServerError();
    }
    
    @Override
    public void handleError(ClientHttpResponse response) throws IOException {
        String body = StreamUtils.copyToString(
            response.getBody(), StandardCharsets.UTF_8);
            
        ErrorResponse error = objectMapper.readValue(body, ErrorResponse.class);
        
        if (response.getStatusCode().is4xxClientError()) {
            throw new ApiClientException(error);
        } else {
            throw new ApiServerException(error);
        }
    }
}
```

## 🧪 **Testing Error Scenarios**

### **Unit Testing Error Responses**

```java
@Test
void shouldReturn401WhenNoAuthenticationProvided() throws Exception {
    mockMvc.perform(get("/api/admin/secure"))
        .andExpect(status().isUnauthorized())
        .andExpected(jsonPath("$.status").value(401))
        .andExpected(jsonPath("$.error").value("Unauthorized"))
        .andExpect(jsonPath("$.message").value("Authentication required"))
        .andExpect(jsonPath("$.path").value("/api/admin/secure"));
}

@Test
void shouldReturn403WhenInsufficientRole() throws Exception {
    mockMvc.perform(get("/api/admin/secure")
            .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
        .andExpect(status().isForbidden())
        .andExpected(jsonPath("$.status").value(403))
        .andExpect(jsonPath("$.error").value("Access Denied"));
}

@Test  
void shouldReturn400WhenInvalidLoginParameters() throws Exception {
    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("username", "")
            .param("password", ""))
        .andExpect(status().isBadRequest())
        .andExpected(jsonPath("$.status").value(400))
        .andExpected(jsonPath("$.details.validationErrors").isArray());
}
```

### **Integration Testing with Error Scenarios**

```java
@Test
void shouldHandleJwtTokenExpiry() {
    // Create expired JWT token
    String expiredToken = jwtUtil.generateExpiredToken("user", "ROLE_USER");
    
    // Make request with expired token
    ResponseEntity<Map> response = restTemplate.exchange(
        "/api/user/secure",
        HttpMethod.GET,
        new HttpEntity<>(createAuthHeaders(expiredToken)),
        Map.class
    );
    
    // Verify error response
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(response.getBody().get("error")).isEqualTo("Unauthorized");
    assertThat(response.getBody().get("details"))
        .extracting("tokenStatus")
        .isEqualTo("EXPIRED");
}
```

## 📊 **Error Response Patterns Summary**

### **Standard Error Response Format**
```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "status": 403,
  "error": "Access Denied",
  "message": "You don't have permission to access this resource",
  "details": {
    "additional": "context-specific information"
  },
  "path": "/api/admin/secure"
}
```

### **Error Response Fields**

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `timestamp` | ISO 8601 | When the error occurred | ✅ |
| `status` | Integer | HTTP status code | ✅ |
| `error` | String | Error category/type | ✅ |
| `message` | String | Human-readable description | ✅ |
| `details` | Object | Additional error context | ❌ |
| `path` | String | Request path that caused error | ✅ |

## 🚀 **Next Steps**

- **[REST Endpoints →](rest-endpoints.md)** - Complete endpoint reference
- **[Authentication Flow →](auth-flow.md)** - Authentication sequence patterns
- **[Security Configuration →](../security/index.md)** - Security implementation details
- **[Testing Examples →](../examples/testing-api.md)** - Comprehensive testing patterns

---

**🚨 Proper error handling improves API usability and debugging. Consistent error response formats help clients handle different error scenarios gracefully and provide better user experiences.**