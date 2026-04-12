# Spring Security Reference Project

A comprehensive educational resource demonstrating advanced Spring Security authentication and authorization patterns.

![Spring Security](https://img.shields.io/badge/Spring%20Security-6.0+-green.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.1+-blue.svg)
![Java](https://img.shields.io/badge/Java-17+-orange.svg)

## 🚀 Quick Start

```bash
# Clone and build
git clone https://github.com/nitikc/spring-security-reference.git
cd spring-security-reference
mvn clean install -DskipTests

# Run the application
mvn spring-boot:run -pl rest-api

# Test it works
curl http://localhost:8080/api/public/hello
```

## 🔐 Testing Authentication (Step-by-Step)

### JWT Authentication (Recommended)

```bash
# 1. Get a JWT token
curl -X POST http://localhost:8080/api/auth/login \
  -d "username=admin&password=password"

# 2. Copy the "token" from response, then use it:
curl http://localhost:8080/api/admin/secure \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### JDBC Authentication (Database Users)

```bash
# Use Basic Auth with database users
curl http://localhost:8080/api/admin/secure \
  -H "Authorization: Basic amRiY2FkbWluOnBhc3N3b3Jk"
```

### 📬 Postman Collection (Easiest Way!)

Import the Postman collection for **automatic JWT token management**:

1. Open Postman → Import → Upload `Spring-Security-Reference-APIs-Enhanced.postman_collection.json`
2. Run "Login as ADMIN" - token is saved automatically!
3. All other requests use the token automatically

## 🔧 What You'll Learn

- **Multiple Authentication Methods**: Database, Directory, OAuth2, JWT
- **Security Architecture**: Filter chains, providers, authorization flows
- **Production Patterns**: BCrypt encoding, token validation, role management
- **Educational Logging**: Comprehensive tracing of all security operations

## 🧪 Demo Credentials

| Method        | Username       | Password        | Role  |
|:--------------|:---------------|:----------------|:------|
| **JWT/Basic** | `admin`        | `password`      | Admin |
| **JWT/Basic** | `user`         | `password`      | User  |
| **JDBC**      | `jdbcadmin`    | `password`      | Admin |
| **JDBC**      | `jdbcuser`     | `password`      | User  |
| **LDAP**      | `ldapadmin`    | `password`      | Admin |
| **LDAP**      | `ldapuser`     | `password`      | User  |
| **OAuth2**    | *Social Login* | *Provider Auth* | User  |

## 📋 API Endpoints

| Endpoint                | Auth Required  | Roles                   |
|:------------------------|:---------------|:------------------------|
| `GET /api/public/hello` | ❌ None         | Any                     |
| `POST /api/auth/login`  | ❌ None         | Any (returns JWT)       |
| `GET /api/auth/info`    | ✅ Yes          | Any authenticated       |
| `GET /api/admin/secure` | ✅ Yes          | ROLE_ADMIN only         |
| `GET /api/user/secure`  | ✅ Yes          | ROLE_USER or ROLE_ADMIN |
| `GET /api/jdbc/users`   | ✅ Yes          | Any authenticated       |
| `GET /api/ldap/users`   | ✅ Yes          | Any authenticated       |
| `GET /actuator/health`  | ❌ None         | Any                     |

## 📖 Local Documentation

To run the documentation site locally:

```bash
pip3 install -r requirements.txt
python3 -m mkdocs serve
```

- Documentation will be available at `http://localhost:8000`


## 📚 **Complete Documentation**

**👉 [Visit the Full Documentation Site](https://nitinkc.github.io/spring-security-reference/) 👈**

- [API Testing Guide](https://nitinkc.github.io/spring-security-reference/examples/testing-api/) - Step-by-step testing
- [Postman Setup](https://nitinkc.github.io/spring-security-reference/examples/postman-setup/) - Collection import guide
- [Start Learning → Full Documentation](https://nitinkc.github.io/spring-security-reference/)