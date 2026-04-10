# Postman Collection Setup Guide

This guide helps you import and use the Postman collection for testing all authentication methods.

---

## 🚀 Quick Import

### Step 1: Download the Collection

The collection file is located at:
```
spring-security-reference/Spring-Security-Reference-APIs-Enhanced.postman_collection.json
```

### Step 2: Import into Postman

1. Open Postman
2. Click **Import** (top-left)
3. Drag the JSON file or click **Upload Files**
4. Click **Import**

You'll see a new collection: **"Spring Security Reference - Complete Testing Suite"**

---

## 🔐 How JWT Auto-Save Works

The collection automatically saves your JWT token! Here's the magic:

### The Flow

```
┌─────────────────────────────────────────────────────────────┐
│  1. Run "Login as ADMIN" request                            │
│     POST /api/auth/login                                    │
│                                                             │
│  2. Response contains token:                                │
│     { "token": "eyJhbGciOi...", "role": "ROLE_ADMIN" }     │
│                                                             │
│  3. Test script AUTO-SAVES token to {{jwtToken}}           │
│     pm.collectionVariables.set('jwtToken', token);         │
│                                                             │
│  4. All other requests use {{jwtToken}} automatically!     │
│     Authorization: Bearer {{jwtToken}}                      │
└─────────────────────────────────────────────────────────────┘
```

### Switch Users Easily

| To login as... | Run this request |
|----------------|------------------|
| Admin (ROLE_ADMIN) | `JWT Auth > 1. Login as ADMIN` |
| User (ROLE_USER) | `JWT Auth > 2. Login as USER` |

The token switches automatically!

---

## 📁 Collection Structure

```
🔑 JWT Authentication
├── 1. Login as ADMIN ⭐        ← Start here!
├── 2. Login as USER
├── 3. Get Auth Info (Who Am I?)
├── 4. Access ADMIN Endpoint
└── 5. Access USER Endpoint

🗄️ JDBC Authentication
├── 1. JDBC Admin - View Users
├── 2. JDBC User - View Users
├── 3. JDBC Admin - Secure Endpoint
└── 4. JDBC User - Secure Endpoint

🏢 LDAP Authentication
├── 1. LDAP Admin - View Users
├── 2. LDAP User - View Users
└── 3. LDAP Admin - Secure Endpoint

🌐 OAuth2 Social Login
├── 1. OAuth2 Profile
├── INFO: Google Login URL
└── INFO: GitHub Login URL

🧪 Error Testing
├── 1. Invalid JWT Token
├── 2. Missing Auth Header
├── 3. Invalid Basic Auth
└── 4. User Accessing Admin (403)

🏥 Health & Public
├── 1. Health Check
└── 2. Public Hello
```

---

## 🎯 Step-by-Step Testing

### Test JWT Authentication

1. **Start the app**: `mvn spring-boot:run -pl rest-api`
2. **Open collection** in Postman
3. **Run** `🔑 JWT Authentication > 1. Login as ADMIN`
4. **Check console** - you'll see "Token saved!"
5. **Run** `4. Access ADMIN Endpoint` - it works!
6. **Run** `🔑 JWT Authentication > 2. Login as USER`
7. **Run** `4. Access ADMIN Endpoint` - now it fails (403)!

### Test JDBC Authentication

1. **Run** `🗄️ JDBC Authentication > 1. JDBC Admin - View Users`
2. Postman automatically sends Basic Auth header
3. **Check response** - shows authenticated user

### Test Error Scenarios

1. **Run** `🧪 Error Testing > 1. Invalid JWT Token`
2. **Check response** - 401 Unauthorized
3. **Run** `4. User Accessing Admin (403)`
4. **Check response** - 403 Forbidden

---

## 🔧 Collection Variables

The collection uses these variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `{{baseUrl}}` | `http://localhost:8080` | API base URL |
| `{{jwtToken}}` | (empty) | Auto-saved JWT token |
| `{{currentUser}}` | (empty) | Current logged-in user |
| `{{currentRole}}` | (empty) | Current user's role |

### Change Base URL

If running on a different port:

1. Click collection name
2. Go to **Variables** tab
3. Change `baseUrl` value
4. Click **Save**

---

## 🏃 Run All Tests at Once

Use Postman's **Collection Runner**:

1. Click **Run** button on collection
2. Select all requests or specific folders
3. Click **Run Collection**
4. Watch all tests execute!

!!! tip "Test Order"
    Run JWT login requests BEFORE other JWT-authenticated requests.

---

## 📋 Quick Reference: All Credentials

### JWT Authentication
| Username | Password | Role |
|----------|----------|------|
| `admin` | `password` | ROLE_ADMIN |
| `user` | `password` | ROLE_USER |

### JDBC (Database) Authentication
| Username | Password | Role |
|----------|----------|------|
| `jdbcadmin` | `password` | ROLE_ADMIN |
| `jdbcuser` | `password` | ROLE_USER |

### LDAP (Directory) Authentication
| Username | Password | Role |
|----------|----------|------|
| `ldapadmin` | `password` | ROLE_ADMIN |
| `ldapuser` | `password` | ROLE_USER |

---

## 🐛 Troubleshooting

### "Could not send request"
- Is the application running?
- Check `baseUrl` is correct

### "Token is empty"
- Run a login request first
- Check the test script executed (green checkmark)

### "401 Unauthorized"
- Token may have expired (24 hour limit)
- Run login again to get a fresh token

### "LDAP requests fail"
- LDAP server is disabled by default
- Enable with: `--spring.ldap.embedded.enabled=true`

---

## 📥 Alternative: VS Code REST Client

If you prefer VS Code, use the `api-testing.http` file:

1. Install **REST Client** extension
2. Open `api-testing.http`
3. Click **Send Request** above any request

The file includes all the same tests with manual token management.

