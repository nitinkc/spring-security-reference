# Complete API Testing Guide

This guide walks you through testing **every authentication method** step-by-step. Follow along to understand how each security mechanism works.

---

## 🚀 Prerequisites

### 1. Start the Application

```bash
# From project root directory
cd spring-security-reference

# Build all modules first
mvn clean install -DskipTests

# Start the REST API (this is the main application)
mvn spring-boot:run -pl rest-api
```

!!! tip "Verify Application Started"
    You should see: `Started RestApiApplication in X seconds`
    
    The app runs on `http://localhost:8080`

### 2. Quick Health Check

```bash
curl http://localhost:8080/api/public/hello
```

**Expected Response:**
```
Hello, world! (public endpoint - no authentication required)
```

If this works, your application is running correctly!

---

## 🔐 Authentication Method 1: JWT Tokens

JWT (JSON Web Token) is the **primary authentication method** for API access. Here's the complete flow:

### Step 1: Generate a JWT Token

```bash
# Login as admin user
curl -X POST http://localhost:8080/api/auth/login \
  -d "username=admin&password=password"
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJST0xFX0FETUlOIiwiaWF0IjoxNzE...",
  "username": "admin",
  "role": "ROLE_ADMIN",
  "message": "Login successful - use this JWT token for authenticated requests",
  "usage": "Add header: Authorization: Bearer eyJhbGciOi..."
}
```

!!! warning "Save Your Token!"
    Copy the `token` value - you'll need it for all subsequent requests.

!!! note "Token Regeneration"
    The application uses `Keys.secretKeyFor()` for secure key generation, which means 
    tokens are invalidated when the application restarts. You'll need to generate a 
    new token after each restart.

### Step 2: Use the JWT Token

```bash
# Replace YOUR_TOKEN with the actual token from Step 1
export JWT_TOKEN="eyJhbGciOiJIUzUxMiJ9..."

# Access admin-only endpoint
curl http://localhost:8080/api/admin/secure \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Response:**
```json
{
  "message": "Hello, Admin! (secured endpoint)",
  "user": "admin",
  "authorities": [{"authority": "ROLE_ADMIN"}],
  "authType": "Custom/Session"
}
```

### Step 3: Test Different Roles

```bash
# Login as regular user
curl -X POST http://localhost:8080/api/auth/login \
  -d "username=user&password=password"

# Save the token and try accessing admin endpoint (should fail!)
export USER_TOKEN="eyJhbGciOi..."

# This will return 403 Forbidden
curl http://localhost:8080/api/admin/secure \
  -H "Authorization: Bearer $USER_TOKEN"

# But user endpoint works
curl http://localhost:8080/api/user/secure \
  -H "Authorization: Bearer $USER_TOKEN"
```

### Step 4: Check Authentication Info

```bash
curl http://localhost:8080/api/auth/info \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Response:**
```json
{
  "authenticated": true,
  "username": "admin",
  "authorities": [{"authority": "ROLE_ADMIN"}],
  "authType": "Custom/Session",
  "principalType": "String"
}
```

---

## 🗄️ Authentication Method 2: JDBC (Database)

JDBC authentication uses database-stored credentials with BCrypt password hashing.

### Available JDBC Users

| Username | Password | Role |
|----------|----------|------|
| `jdbcadmin` | `password` | `ROLE_ADMIN` |
| `jdbcuser` | `password` | `ROLE_USER` |

### Test JDBC Authentication

```bash
# First, get a JWT token using JDBC credentials
curl -X POST http://localhost:8080/api/auth/login \
  -d "username=jdbcadmin&password=password"

# Use the token to access JDBC demo endpoint
export JDBC_TOKEN="eyJhbGciOi..."

curl http://localhost:8080/api/jdbc/users \
  -H "Authorization: Bearer $JDBC_TOKEN"
```

**Response:**
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

---

## 🏢 Authentication Method 3: LDAP

LDAP authentication uses an embedded LDAP directory server.

### Available LDAP Users

| Username | Password | Role |
|----------|----------|------|
| `ldapadmin` | `password` | `ROLE_ADMIN` |
| `ldapuser` | `password` | `ROLE_USER` |

### Test LDAP Authentication

```bash
# Get a JWT token using LDAP credentials
curl -X POST http://localhost:8080/api/auth/login \
  -d "username=ldapadmin&password=password"

# Use the token to access LDAP demo endpoint
export LDAP_TOKEN="eyJhbGciOi..."

curl http://localhost:8080/api/ldap/users \
  -H "Authorization: Bearer $LDAP_TOKEN"
```

**Response:**
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

---

## 🌐 Authentication Method 4: OAuth2

OAuth2 authentication uses external identity providers (GitHub, Google, etc.).

!!! note "Current Status"
    OAuth2 integration is currently commented out in `MultiAuthSecurityConfig`. 
    To test OAuth2, uncomment the `oauth2Login()` configuration block and configure 
    your OAuth2 provider credentials in `application.yml`.

### Test OAuth2 Profile Endpoint

```bash
# After OAuth2 login, access the profile endpoint
curl http://localhost:8080/api/oauth2/profile \
  -H "Authorization: Bearer $OAUTH_TOKEN"
```

**Response (when authenticated via OAuth2):**
```json
{
  "message": "OAuth2 Authentication Demo",
  "user": "github-username",
  "email": "user@example.com",
  "provider": "OAuth2",
  "attributes": { ... }
}
```

---

## 📋 Complete Endpoint Reference

### Public Endpoints (No Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/public/hello` | GET | Public hello message |
| `/api/auth/login` | POST | Generate JWT token |
| `/actuator/health` | GET | Health check |

### Authenticated Endpoints

| Endpoint | Method | Required Role | Description |
|----------|--------|---------------|-------------|
| `/api/auth/info` | GET | Any authenticated | Current auth details |
| `/api/admin/secure` | GET | `ROLE_ADMIN` | Admin-only endpoint |
| `/api/user/secure` | GET | `ROLE_USER` or `ROLE_ADMIN` | User endpoint |
| `/api/jdbc/users` | GET | `ROLE_USER` or `ROLE_ADMIN` | JDBC auth demo |
| `/api/ldap/users` | GET | `ROLE_USER` or `ROLE_ADMIN` | LDAP auth demo |
| `/api/oauth2/profile` | GET | Any authenticated | OAuth2 profile |

---

## 🧪 Quick Test Script

Save this as `test-api.sh` and run it to test all endpoints:

```bash
#!/bin/bash

BASE_URL="http://localhost:8080"

echo "=== Testing Public Endpoint ==="
curl -s $BASE_URL/api/public/hello
echo -e "\n"

echo "=== Getting Admin JWT Token ==="
ADMIN_RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/login -d "username=admin&password=password")
echo $ADMIN_RESPONSE | jq .
ADMIN_TOKEN=$(echo $ADMIN_RESPONSE | jq -r '.token')

echo "=== Testing Admin Endpoint ==="
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" $BASE_URL/api/admin/secure | jq .

echo "=== Testing User Endpoint ==="
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" $BASE_URL/api/user/secure | jq .

echo "=== Testing Auth Info ==="
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" $BASE_URL/api/auth/info | jq .

echo "=== Getting User JWT Token ==="
USER_RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/login -d "username=user&password=password")
USER_TOKEN=$(echo $USER_RESPONSE | jq -r '.token')

echo "=== Testing Admin Endpoint with User Token (should fail) ==="
curl -s -H "Authorization: Bearer $USER_TOKEN" $BASE_URL/api/admin/secure
echo -e "\n"

echo "=== All tests completed ==="
```

---

## 🔗 Related Topics

- [REST Endpoints Reference](../api/rest-endpoints.md)
- [JWT Tokens](../authentication/jwt-tokens.md)
- [Security Configuration](../security/common-security.md)
