# Project Architecture and Flow Diagrams

This page provides a detailed visual reference for the architecture, authentication flows, and security mechanisms used in the Spring Security Reference Project.

## 1. Overall Project Architecture

This diagram illustrates the modular architecture of the project, showing how different services and components are interconnected. The `rest-api` module is the central entry point, consuming functionality from various authentication and security modules.

```mermaid
graph TD
    subgraph "Entry Points"
        A[rest-api]
    end

    subgraph "Core Security Modules"
        B[common-security]
        C[common-auth]
    end

    subgraph "Authentication Providers"
        D[jdbc-auth]
        E[ldap-auth]
        F[oauth2-auth]
    end

    subgraph "Authorization"
        G[authorization-service]
    end

    subgraph "External Systems"
        H[(Database)]
        I[LDAP Directory]
        J[OAuth2 Providers]
    end

    A --> B
    A --> C
    A --> D
    A --> E
    A --> F
    A --> G
    
    B --> C
    D --> H
    E --> I
    F --> J

    style A fill:#D5E8D4,stroke:#82B366
    style B fill:#F8CECC,stroke:#B85450
    style C fill:#F8CECC,stroke:#B85450
    style D fill:#DAE8FC,stroke:#6C8EBF
    style E fill:#DAE8FC,stroke:#6C8EBF
    style F fill:#DAE8FC,stroke:#6C8EBF
    style G fill:#E1D5E7,stroke:#9673A6
```

### Key Takeaways:
- **Modular Design**: Each authentication method (`jdbc-auth`, `ldap-auth`, `oauth2-auth`) is a separate module.
- **Shared Logic**: `common-auth` and `common-security` provide reusable security configurations and utilities.
- **Centralized API**: The `rest-api` module integrates all security features and exposes the endpoints.

---

## 2. Authentication Flow - Session-Based Login

This sequence diagram shows the step-by-step process for a traditional, session-based user login.

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant SpringSecurity as Security Filter Chain
    participant CustomAuthProvider as CustomAuthenticationProvider
    participant AuthService as AuthService
    participant SessionRegistry

    User->>Browser: Submits username & password
    Browser->>SpringSecurity: POST /login
    SpringSecurity->>CustomAuthProvider: authenticate(Authentication)
    CustomAuthProvider->>AuthService: authenticateSession(username, password)
    AuthService-->>CustomAuthProvider: UserDetails (or throws Exception)
    CustomAuthProvider-->>SpringSecurity: return new UsernamePasswordAuthenticationToken
    SpringSecurity->>SessionRegistry: Creates new Session
    SpringSecurity->>Browser: Redirect to home, Set JSESSIONID Cookie
    Browser->>User: Displays logged-in page
```

### Flow Explanation:
1.  The user submits their credentials via a login form.
2.  Spring Security's filter chain intercepts the request.
3.  The `CustomAuthenticationProvider` is invoked.
4.  It delegates the core authentication logic to the `AuthService`.
5.  If successful, an `Authentication` object is returned and stored in the `SecurityContext`.
6.  A `JSESSIONID` cookie is created, and the user is logged in.

---

## 3. Authentication Flow - JWT-Based Login

This diagram details the process of obtaining and using a JSON Web Token (JWT) for stateless authentication.

```mermaid
sequenceDiagram
    participant User
    participant ClientApp as Client Application
    participant ApiService as /api/auth/login
    participant JwtTokenUtil
    participant SecuredEndpoint as /api/admin/*
    participant JwtAuthFilter as JwtAuthenticationFilter

    User->>ClientApp: Enters credentials
    ClientApp->>ApiService: POST with username & password
    ApiService->>JwtTokenUtil: generateToken(userDetails)
    JwtTokenUtil-->>ApiService: Returns JWT (Access Token)
    ApiService-->>ClientApp: Sends JWT to client
    ClientApp->>User: Stores JWT securely (e.g., memory)

    User->>ClientApp: Clicks on a secured action
    ClientApp->>SecuredEndpoint: Request with "Authorization: Bearer <JWT>" header
    SecuredEndpoint->>JwtAuthFilter: Intercepts request
    JwtAuthFilter->>JwtTokenUtil: validateToken(JWT)
    JwtTokenUtil-->>JwtAuthFilter: Returns Claims (username, roles)
    JwtAuthFilter->>SpringSecurity: Sets SecurityContextHolder
    SecuredEndpoint-->>ClientApp: Returns secured resource
```

### Flow Explanation:
1.  The user logs in at a dedicated endpoint (`/api/auth/login`).
2.  The server validates credentials and uses `JwtTokenUtil` to generate a token.
3.  The token is sent back to the client.
4.  For subsequent requests to secured endpoints, the client sends the JWT in the `Authorization` header.
5.  The `JwtAuthenticationFilter` intercepts the request, validates the token, and sets the security context, allowing access.

---

## 4. Spring Security Filter Chain

This diagram visualizes the key filters in the Spring Security chain and their order of execution.

```mermaid
graph LR
    subgraph "Flow"
        Req(Request) --> F1[CsrfFilter]
        F1 --> F2[HeaderWriterFilter]
        F2 --> F3[JwtAuthenticationFilter]
        F3 --> F4[UsernamePasswordAuthenticationFilter]
        F4 --> F5[AuthorizationFilter]
        F5 --> Controller(Controller Endpoint)
    end

    style F1 fill:#F8CECC,stroke:#B85450
    style F2 fill:#F8CECC,stroke:#B85450
    style F3 fill:#DAE8FC,stroke:#6C8EBF
    style F4 fill:#DAE8FC,stroke:#6C8EBF
    style F5 fill:#D5E8D4,stroke:#82B366
```

### Filter Descriptions:
- **`CsrfFilter`**: Protects against Cross-Site Request Forgery attacks.
- **`HeaderWriterFilter`**: Adds security-related headers to the response (e.g., `X-Content-Type-Options`).
- **`JwtAuthenticationFilter`**: (Custom) Validates JWTs from the `Authorization` header.
- **`UsernamePasswordAuthenticationFilter`**: Handles form-based login submissions.
- **`AuthorizationFilter`**: Enforces access control rules on endpoints based on user roles/permissions.

---

## 5. Authorization Logic

This flowchart explains how the system determines if a user has permission to access a secured resource.

```mermaid
graph TD
    A[User requests secured endpoint] --> B{Is user authenticated?};
    B -- No --> C[Access Denied (401 Unauthorized)];
    B -- Yes --> D{Endpoint requires specific role?};
    D -- No --> E[Access Granted];
    D -- Yes --> F{Does user have the required role?};
    F -- No --> G[Access Denied (403 Forbidden)];
    F -- Yes --> H{Endpoint requires specific permission?};
    H -- No --> E;
    H -- Yes --> I{Does user's role have the permission?};
    I -- No --> G;
    I -- Yes --> E;

    style C fill:#F8CECC,stroke:#B85450
    style G fill:#F8CECC,stroke:#B85450
    style E fill:#D5E8D4,stroke:#82B366
```

### Logic Explanation:
1.  The system first checks if the user is authenticated at all.
2.  It then checks if the requested endpoint is protected by a specific role (e.g., `ROLE_ADMIN`).
3.  If a role is required, it verifies the user has that role.
4.  Finally, for more granular control, it can check for specific permissions associated with the user's role (e.g., `CAN_DELETE_USER`).
5.  Access is only granted if all checks pass.

---

## 6. gRPC and WebSocket Security Interception

These diagrams show how security is applied to non-HTTP protocols like gRPC and WebSockets using interceptors.

### gRPC Security Interceptor

```mermaid
sequenceDiagram
    participant Client
    participant GrpcServer as gRPC Server
    participant GrpcSecurityInterceptor as Security Interceptor
    participant JwtTokenUtil
    participant ServiceImpl as gRPC Service Implementation

    Client->>GrpcServer: gRPC call with JWT in Metadata
    GrpcServer->>GrpcSecurityInterceptor: interceptCall(call, headers)
    GrpcSecurityInterceptor->>JwtTokenUtil: Validate JWT from headers
    alt Invalid Token
        GrpcSecurityInterceptor-->>Client: close(Status.UNAUTHENTICATED)
    else Valid Token
        GrpcSecurityInterceptor->>ServiceImpl: forward(call, headers)
        ServiceImpl-->>GrpcSecurityInterceptor: Response
        GrpcSecurityInterceptor-->>Client: Response
    end
```

### WebSocket Security Interceptor

```mermaid
sequenceDiagram
    participant Client
    participant WebSocketBroker
    participant WebSocketSecurityInterceptor as Security Interceptor
    participant JwtTokenUtil

    Client->>WebSocketBroker: CONNECT frame with JWT
    WebSocketBroker->>WebSocketSecurityInterceptor: preSend(message, channel)
    WebSocketSecurityInterceptor->>JwtTokenUtil: Validate JWT from message headers
    alt Invalid Token
        WebSocketSecurityInterceptor-->>Client: Throw AuthenticationException
    else Valid Token
        WebSocketSecurityInterceptor->>WebSocketBroker: Allow message processing
    end
```

### Interceptor Explanation:
- **gRPC**: An interceptor extracts the JWT from the call's `Metadata` (headers), validates it, and either closes the call with an `UNAUTHENTICATED` status or forwards it to the service implementation.
- **WebSocket**: A `ChannelInterceptor` inspects messages on the channel. The `preSend` method is used to validate a JWT sent during the `CONNECT` phase, preventing unauthorized clients from subscribing or sending messages.
