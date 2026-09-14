# Quick Setup

Get the Spring Security Reference Project running on your local machine in just a few minutes.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

| Tool | Version | Purpose |
|------|---------|---------|
| **Java** | 17+ | Runtime environment |
| **Gradle Wrapper** | Included | Build and dependency management |
| **Git** | Latest | Version control |
| **IDE** | IntelliJ IDEA, Eclipse, or VS Code | Development environment |

### Verify Prerequisites

```bash
# Check Java version
java -version

# Check the Gradle wrapper
./gradlew --version

# Check Git version
git --version
```

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd spring-security-reference
```

### 2. Build the Project

```bash
# Clean install all modules
./gradlew build

# Verify build success
echo "Build completed successfully!"
```

### 3. Run the Application

```bash
# Start the main application
./gradlew :rest-api:bootRun
```

The application will start on `http://localhost:8080`

## ✅ Verify Installation

### Test Public Endpoint

```bash
curl http://localhost:8080/api/public/hello
```

Expected response:
```
Hello, world! (public endpoint - no authentication required)
```

### Test Authentication

```bash
# Get JWT token
curl -X POST http://localhost:8080/api/auth/login \
  -d "username=admin&password=password"
```

Expected response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "username": "admin",
  "role": "ROLE_ADMIN",
  "message": "Login successful - use this JWT token for authenticated requests",
  "usage": "Add header: Authorization: Bearer <token>"
}
```

### Test Secured Endpoint

```bash
# Use the token from previous step
curl -H "Authorization: Bearer <your-jwt-token>" \
  http://localhost:8080/api/admin/secure
```

Expected response:
```json
{
  "message": "Hello, Admin! (secured endpoint)",
  "user": "admin",
  "authorities": ["ROLE_ADMIN"],
  "authType": "JWT"
}
```

## 🔧 Development Setup

### IDE Configuration

#### IntelliJ IDEA

1. **Import Project**: File → Open → Select the repository root `settings.gradle`
2. **Enable Annotation Processing**: Settings → Build → Compiler → Annotation Processors
3. **Set JDK**: File → Project Structure → Project → SDK: Java 21

#### Eclipse

1. **Import Project**: File → Import → Gradle → Existing Gradle Project
2. **Select Root Directory**: Browse to project folder
3. **Configure JDK**: Right-click project → Properties → Java Build Path

#### VS Code

1. **Open Folder**: File → Open Folder → Select project directory
2. **Install Extensions**:
   - Extension Pack for Java
   - Spring Boot Extension Pack
3. **Configure Java**: Ctrl+Shift+P → "Java: Configure Runtime"

### Environment Variables

Set up optional environment variables for customization:

```bash
# Application port (default: 8080)
export SERVER_PORT=8080

# Active profiles (default: default)
export SPRING_PROFILES_ACTIVE=default

# Log level (default: INFO)
export LOGGING_LEVEL_ROOT=INFO
```

## 🧪 Testing Setup

### Run All Tests

```bash
# Execute all unit and integration tests
./gradlew test
```

### Module-Specific Testing

```bash
# Test specific authentication modules
./gradlew test -pl jdbc-auth
./gradlew test -pl ldap-auth
./gradlew test -pl oauth2-auth
```

### HTTP Testing

Use the provided `api-testing.http` file with your IDE's HTTP client:

1. **IntelliJ IDEA**: Open `api-testing.http` → Click play buttons
2. **VS Code**: Install REST Client extension → Open file → Send requests
3. **Postman**: Import the collection (export available)

## 🐳 Docker Setup (Optional)

For containerized development:

### Build Docker Image

```bash
# Build application image
docker build -t spring-security-ref .
```

### Run with Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Services Available

- **Application**: `http://localhost:8080`
- **Database**: `localhost:5432` (PostgreSQL)
- **LDAP**: `localhost:8389` (Embedded)

## 📊 Application Profiles

The application supports multiple profiles for different scenarios:

| Profile | Description | Modules Active |
|---------|-------------|----------------|
| `default` | All authentication methods | All modules |
| `jdbc-only` | Database authentication only | jdbc-auth, common-* |
| `ldap-only` | LDAP authentication only | ldap-auth, common-* |
| `oauth2-only` | OAuth2 authentication only | oauth2-auth, common-* |

### Activate Specific Profile

```bash
# JDBC authentication only
./gradlew :rest-api:bootRun -Dspring-boot.run.profiles=jdbc-only

# LDAP authentication only  
./gradlew :rest-api:bootRun -Dspring-boot.run.profiles=ldap-only
```

## 🔍 Troubleshooting

### Common Issues

#### Port Already in Use

```bash
# Find process using port 8080
netstat -ano | findstr :8080    # Windows
lsof -i :8080                   # macOS/Linux

# Kill the process or use different port
./gradlew :rest-api:bootRun -Dspring-boot.run.arguments=--server.port=8081
```

#### Java Version Issues

```bash
# Set JAVA_HOME
export JAVA_HOME=/path/to/java17    # macOS/Linux
set JAVA_HOME=C:\path\to\java17     # Windows

# Verify Gradle uses the expected Java runtime
./gradlew --version
```

#### Build Failures

```bash
# Clean and rebuild
./gradlew clean classes

# Skip tests if needed
./gradlew build -x test
```

### Getting Help

- 📖 **Documentation**: Browse the [troubleshooting guide](../reference/troubleshooting.md)
- 🔍 **Logs**: Check application logs for detailed error messages
- 💬 **Community**: Ask questions in project discussions

## 🎉 Success!

You now have the Spring Security Reference Project running locally! 

### What's Next?

- **[Project Structure →](project-structure.md)** Explore the codebase organization
- **[Authentication Methods →](../authentication/index.md)** Learn about different auth strategies
- **[API Testing →](../examples/testing-auth.md)** Try out the endpoints

## 💡 Pro Tips

- **Use HTTP files**: The `api-testing.http` file contains all example requests
- **Check logs**: Educational logging explains every security operation
- **Try different profiles**: Each profile demonstrates specific authentication methods
- **Explore modules**: Each authentication method is in its own independent module