# Spring Security Reference Project - AI Coding Instructions

This is an educational Spring Security reference implementation demonstrating advanced authentication and authorization patterns across REST, gRPC, and WebSocket protocols.

## Architecture Overview

This project uses a **layered modular architecture** with clear separation of concerns:

- **`common-auth`**: Authentication logic (session-based, JWT, 2FA hooks)  
- **`common-security`**: Security configuration, filters, and interceptors
- **`authorization-service`**: Role/permission management service
- **`api-service`**: REST endpoints with security integration

## Key Patterns & Conventions

### Authentication Flow Architecture
The project implements **dual authentication modes**:
1. **Session-based**: Uses `CustomAuthenticationProvider` with `AuthService.authenticateSession()`
2. **JWT-based**: Uses `JwtAuthenticationFilter` with `JwtTokenUtil` for token validation

**Critical**: All authentication flows converge through the `SecurityConfig` filter chain - never bypass this pattern.

### Module Dependencies
Follow this **strict dependency hierarchy**:
```
api-service → common-auth + common-security + authorization-service
common-security → common-auth
authorization-service → standalone
common-auth → standalone
```

### JWT Token Patterns
- **Generation**: Always include both `username` (subject) and `role` claims in `JwtTokenUtil.generateToken()`
- **Validation**: Extract both from `Claims` object in `JwtAuthenticationFilter.doFilterInternal()`  
- **Headers**: Use `Authorization: Bearer <token>` format consistently across REST/gRPC

### Role-Based Security
- **Naming Convention**: All roles use `ROLE_` prefix (e.g., `ROLE_ADMIN`, `ROLE_USER`)
- **Authorization**: Check roles via `AuthorizationService.getUserRole()` and permissions via `hasPermission()`
- **Hardcoded Users**: `admin/password` → `ROLE_ADMIN`, `user/*` → `ROLE_USER`

## Protocol-Specific Security

### REST Endpoints (ApiController)
- **Public**: `/api/public/*` - no authentication required
- **Role-based**: `/api/admin/*` requires `ROLE_ADMIN`, `/api/user/*` requires `ROLE_USER`  
- **Login**: POST `/api/auth/login` returns JWT token directly

### gRPC Security (GrpcSecurityInterceptor)
- Extract JWT from `Authorization` metadata header
- Validate with `Bearer ` prefix requirement
- Close call with `Status.UNAUTHENTICATED` for invalid tokens

### WebSocket Security (WebSocketSecurityInterceptor)
- Implement security in `preSend()` method of `ChannelInterceptor`
- Currently allows all messages - extend for JWT validation

## Development Guidelines

### When Adding New Endpoints
1. Add to appropriate controller in `api-service`
2. Configure security rules in `SecurityConfig` if needed
3. Use `@Autowired` for `JwtTokenUtil` and `AuthorizationService`
4. Follow existing role-based access patterns

### When Extending Authentication
1. **Session-based**: Modify `CustomAuthenticationProvider` and `AuthService.authenticateSession()`
2. **JWT-based**: Extend `JwtTokenUtil` for additional claims or validation
3. **2FA**: Use `TwoFactorAuthService.verifyTOTP()` as integration hook

### When Adding Security Interceptors
- Implement the appropriate interface (`ServerInterceptor`, `ChannelInterceptor`)
- Register in `SecurityConfig` bean configuration
- Always provide clear error messages for authentication failures

## Critical Implementation Details

- **Filter Order**: JWT filter runs before custom authentication provider in the Spring Security chain
- **Security Context**: Always set authentication in `SecurityContextHolder` for downstream authorization
- **Error Handling**: Use specific Spring Security exceptions, not generic `Exception` types
- **Token Expiration**: Default JWT expiry is 24 hours (`EXPIRATION_TIME = 86400000`)
- **Secret Key**: Uses hardcoded `"MySuperSecretKey"` - replace in production environments

## Teaching Focus
This codebase prioritizes **clear demonstration of concepts** over production readiness. When extending:
- Maintain educational comments explaining Spring Security concepts
- Keep examples simple and focused on the security pattern being demonstrated
- Preserve the modular structure to show proper separation of security concerns