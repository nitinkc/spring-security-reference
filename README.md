# Spring Security Reference Project

A comprehensive educational resource demonstrating advanced Spring Security authentication and authorization patterns.

![Spring Security](https://img.shields.io/badge/Spring%20Security-6.0+-green.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5+-blue.svg)
![Java](https://img.shields.io/badge/Java-21-orange.svg)

## Resume reminder

Before starting new work, open **[Project Progress and Resume Point](docs/progress.md)**. It is the single source for completed labs, the exact next lab, known limitations, and verification commands.

Current resume point: **LAB-031 — WebSocket Security**. Do not infer progress from the number of documentation pages; only labs listed as completed in `docs/progress.md` have executable evidence.

## 🚀 Quick Start

```bash
# Clone and build
git clone https://github.com/nitikc/spring-security-reference.git
cd spring-security-reference
./gradlew build -x test

# Run the application
./gradlew :rest-api:bootRun

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

- **Authentication Methods**: Database, directory, OAuth2/OIDC, SAML 2.0, and JWT
- **Single Sign-On**: OIDC and SAML trust models, sessions, logout, threats, and labs
- **Security Architecture**: Filter chains, providers, authorization flows, and service identity
- **Hands-on Learning**: 58 ordered labs with positive, negative, and attack-case tests
- **Senior Assessments**: Interactive scenario quizzes for internals, SSO, microservices, and operations
- **Advanced Platform Security**: Authorization server, SCIM, WebFlux, gateway, multi-tenancy, Kafka, supply chain, and data protection

OAuth2/OIDC, SSO, and SAML are currently Theory/Planned capabilities. Follow [LAB-010 through LAB-020](docs/labs.md) to implement them, then LAB-047 through LAB-058 for advanced identity and platform coverage.

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
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
python3 -m mkdocs serve
```

- Documentation will be available at `http://localhost:8000`


## 📚 **Complete Documentation**

**👉 [Visit the Full Documentation Site](https://nitinkc.github.io/spring-security-reference/) 👈**

- [API Testing Guide](https://nitinkc.github.io/spring-security-reference/examples/testing-api/) - Step-by-step testing
- [Postman Setup](https://nitinkc.github.io/spring-security-reference/examples/postman-setup/) - Collection import guide
- [Start Learning → Full Documentation](https://nitinkc.github.io/spring-security-reference/)