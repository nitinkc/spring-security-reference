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
mvn clean install

# Run the application
mvn spring-boot:run -pl rest-api

# Test authentication
curl -X POST http://localhost:8080/api/auth/login -d "username=admin&password=password"
```

## 📚 **Complete Documentation**

**👉 [Visit the Full Documentation Site](https://nitikc.github.io/spring-security-reference) 👈**

The comprehensive documentation includes:

- 🏗️ **Architecture & Setup** - Project structure and quick start
- 🔐 **Authentication Methods** - JDBC, LDAP, OAuth2, JWT guides  
- 🛡️ **Security Configuration** - Filters, providers, and authorization
- 🌐 **API Reference** - Complete endpoint documentation and testing
- 📖 **Examples & Tutorials** - Step-by-step implementation guides
- 🚀 **Production Deployment** - Security best practices and setup

## 🔧 What You'll Learn

- **Multiple Authentication Methods**: Database, Directory, OAuth2, JWT
- **Security Architecture**: Filter chains, providers, authorization flows
- **Production Patterns**: BCrypt encoding, token validation, role management
- **Educational Logging**: Comprehensive tracing of all security operations

## 🧪 Demo Credentials

| Method | Username | Password | Role |
|--------|----------|----------|------|
| **JWT/Basic** | `admin` | `password` | Admin |
| **JDBC** | `jdbcadmin` | `password` | Admin |
| **LDAP** | `ldapadmin` | `password` | Admin |
| **OAuth2** | *Social Login* | *Provider Auth* | User |

## 📖 Local Documentation

To run the documentation site locally:

```bash
pip install -r requirements.txt
python -m mkdocs serve
```

Documentation will be available at `http://localhost:8000`

## 🤝 Contributing

This educational project welcomes contributions that enhance learning! See the [documentation site](https://nitikc.github.io/spring-security-reference) for detailed guides.

## 📄 License

MIT License - Use freely for learning and reference.

---

**📚 [Start Learning → Full Documentation](https://nitikc.github.io/spring-security-reference)**