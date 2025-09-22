# LDAP Authentication

Comprehensive guide to Lightweight Directory Access Protocol (LDAP) authentication in Spring Security. Learn how to integrate with directory services like Active Directory and OpenLDAP.

## 🏢 **LDAP Overview**

LDAP authentication allows integration with enterprise directory services, providing centralized user management and authentication.

```mermaid
sequenceDiagram
    participant U as User
    participant A as Application
    participant L as LDAP Server
    participant D as Directory
    
    Note over U,D: LDAP Authentication Flow
    U->>A: Login (username/password)
    A->>L: Bind request with credentials
    L->>D: Authenticate against directory
    D-->>L: Authentication result
    L-->>A: Success + User attributes
    A->>A: Load user authorities
    A->>A: Create Security Context
    A-->>U: Authentication successful
```

## 🔧 **LDAP Configuration**

### **Embedded LDAP Server (Testing)**

```java
@Configuration
@Profile("ldap")
public class LdapConfig {
    
    private static final Logger logger = LogManager.getLogger(LdapConfig.class);
    
    @Bean
    public ContextSource contextSource() {
        logger.info("🏢 [LDAP-CONFIG] Configuring embedded LDAP server");
        logger.debug("📚 [LEARNING] Embedded LDAP is for testing - use external LDAP in production");
        
        return new EmbeddedLdapServerContextSourceFactoryBean()
                .setLdif("classpath:users.ldif")
                .setBase("dc=springframework,dc=org")
                .setPort(8389)
                .getContextSource();
    }
    
    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        logger.info("🔐 [LDAP-CONFIG] Setting up LDAP authentication provider");
        
        // Bind authenticator - authenticates by binding to LDAP
        BindAuthenticator authenticator = new BindAuthenticator(contextSource());
        authenticator.setUserDnPatterns(new String[]{"uid={0},ou=people"});
        
        // Authorities populator - loads user roles from LDAP groups
        DefaultLdapAuthoritiesPopulator authoritiesPopulator = 
                new DefaultLdapAuthoritiesPopulator(contextSource(), "ou=groups");
        authoritiesPopulator.setGroupRoleAttribute("cn");
        authoritiesPopulator.setGroupSearchFilter("member={0}");
        authoritiesPopulator.setRolePrefix("ROLE_");
        authoritiesPopulator.setConvertToUpperCase(true);
        
        LdapAuthenticationProvider provider = 
                new LdapAuthenticationProvider(authenticator, authoritiesPopulator);
                
        logger.debug("✅ [LDAP-CONFIG] LDAP authentication provider configured");
        logger.debug("📚 [LEARNING] Users authenticated via LDAP bind operation");
        
        return provider;
    }
}
```

### **External LDAP Server Configuration**

```java
@Configuration
@Profile("ldap-production")
public class ExternalLdapConfig {
    
    @Value("${ldap.url:ldap://localhost:389}")
    private String ldapUrl;
    
    @Value("${ldap.base:dc=example,dc=com}")
    private String ldapBase;
    
    @Value("${ldap.username:}")
    private String ldapUsername;
    
    @Value("${ldap.password:}")
    private String ldapPassword;
    
    @Bean
    public ContextSource contextSource() {
        LdapContextSource context = new LdapContextSource();
        context.setUrl(ldapUrl);
        context.setBase(ldapBase);
        
        // Manager credentials for searching
        if (!ldapUsername.isEmpty()) {
            context.setUserDn(ldapUsername);
            context.setPassword(ldapPassword);
        }
        
        context.afterPropertiesSet();
        return context;
    }
    
    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        // Search and bind pattern
        FilterBasedLdapUserSearch userSearch = 
                new FilterBasedLdapUserSearch("", "(uid={0})", contextSource());
                
        BindAuthenticator authenticator = new BindAuthenticator(contextSource());
        authenticator.setUserSearch(userSearch);
        
        // Custom authorities populator
        DefaultLdapAuthoritiesPopulator authoritiesPopulator = 
                new DefaultLdapAuthoritiesPopulator(contextSource(), "ou=roles");
        authoritiesPopulator.setGroupRoleAttribute("cn");
        authoritiesPopulator.setGroupSearchFilter("uniqueMember={0}");
        
        return new LdapAuthenticationProvider(authenticator, authoritiesPopulator);
    }
}
```

## 📊 **LDIF Test Data**

### **users.ldif**
```ldif
dn: dc=springframework,dc=org
objectclass: top
objectclass: domain
objectclass: extensibleObject
dc: springframework

dn: ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=people,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: people

# Users
dn: uid=ldapadmin,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: LDAP Admin
sn: Admin
uid: ldapadmin
userPassword: password

dn: uid=ldapuser,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: LDAP User
sn: User
uid: ldapuser
userPassword: password

# Groups
dn: cn=ADMIN,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfNames
cn: ADMIN
member: uid=ldapadmin,ou=people,dc=springframework,dc=org

dn: cn=USER,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfNames
cn: USER
member: uid=ldapuser,ou=people,dc=springframework,dc=org
member: uid=ldapadmin,ou=people,dc=springframework,dc=org
```

## 🔐 **Security Configuration**

### **LDAP Security Filter Chain**

```java
@Configuration
@EnableWebSecurity
@Profile("ldap")
public class LdapSecurityConfig {
    
    private static final Logger logger = LogManager.getLogger(LdapSecurityConfig.class);
    
    @Autowired
    private LdapAuthenticationProvider ldapAuthenticationProvider;
    
    @Bean
    public SecurityFilterChain ldapFilterChain(HttpSecurity http) throws Exception {
        logger.info("🔐 [LDAP-SECURITY] Configuring LDAP security filter chain");
        logger.debug("📚 [LEARNING] LDAP authentication via HTTP Basic Auth");
        
        return http
            .authenticationProvider(ldapAuthenticationProvider)
            
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/ldap/**").authenticated()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            
            .httpBasic(basic -> basic
                .realmName("LDAP Authentication")
            )
            
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            )
            
            .csrf(csrf -> csrf.disable())
            
            .build();
    }
}
```

## 🚀 **Usage Examples**

### **1. LDAP Authentication with cURL**

```bash
# Authenticate LDAP admin user
curl -u ldapadmin:password \
  http://localhost:8080/api/ldap/users

# Authenticate LDAP regular user  
curl -u ldapuser:password \
  http://localhost:8080/api/ldap/users

# Base64 encoded credentials
curl -H "Authorization: Basic bGRhcGFkbWluOnBhc3N3b3Jk" \
  http://localhost:8080/api/ldap/users
```

### **2. LDAP Response Example**

```json
{
  "message": "LDAP Authentication Demo",
  "user": "ldapadmin",
  "credentials": {
    "ldapadmin": "password (ROLE_ADMIN)",
    "ldapuser": "password (ROLE_USER)"
  },
  "authType": "LDAP",
  "authorities": [
    {
      "authority": "ROLE_ADMIN"
    },
    {
      "authority": "ROLE_USER"
    }
  ]
}
```

## 🔍 **Custom LDAP User Details**

### **LdapUserDetailsMapper**

```java
@Component
public class CustomLdapUserDetailsMapper implements UserDetailsContextMapper {
    
    private static final Logger logger = LogManager.getLogger(CustomLdapUserDetailsMapper.class);
    
    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, 
                                          String username, 
                                          Collection<? extends GrantedAuthority> authorities) {
        
        logger.debug("🔍 [LDAP-MAPPER] Mapping LDAP user: {}", username);
        
        // Extract additional LDAP attributes
        String fullName = ctx.getStringAttribute("cn");
        String email = ctx.getStringAttribute("mail");
        String department = ctx.getStringAttribute("departmentNumber");
        
        logger.debug("📊 [LDAP-MAPPER] User attributes:");
        logger.debug("   • Full Name: {}", fullName);
        logger.debug("   • Email: {}", email);
        logger.debug("   • Department: {}", department);
        logger.debug("   • Authorities: {}", authorities);
        
        // Create custom user details with LDAP attributes
        return LdapUserDetails.builder()
                .username(username)
                .password("[PROTECTED]")
                .authorities(authorities)
                .fullName(fullName)
                .email(email)
                .department(department)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .enabled(true)
                .build();
    }
    
    @Override
    public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
        // Used for user creation/update - not typically needed for authentication
        logger.debug("🔄 [LDAP-MAPPER] Mapping user to LDAP context: {}", user.getUsername());
    }
}
```

### **Custom LDAP User Details Class**

```java
public class LdapUserDetails implements UserDetails {
    
    private final String username;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;
    private final String fullName;
    private final String email;
    private final String department;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;
    private final boolean enabled;
    
    // Constructor, getters, and builder pattern implementation
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    
    // Additional getters for LDAP attributes
    public String getFullName() {
        return fullName;
    }
    
    public String getEmail() {
        return email;
    }
    
    public String getDepartment() {
        return department;
    }
}
```

## 🧪 **Testing LDAP Authentication**

### **Integration Tests**

```java
@SpringBootTest
@ActiveProfiles("ldap")
@TestPropertySource(properties = {
    "logging.level.org.springframework.ldap=DEBUG"
})
class LdapAuthenticationTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    void shouldAuthenticateLdapAdminUser() {
        // Test LDAP admin authentication
        ResponseEntity<Map> response = restTemplate
                .withBasicAuth("ldapadmin", "password")
                .getForEntity("/api/ldap/users", Map.class);
                
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("user")).isEqualTo("ldapadmin");
    }
    
    @Test
    void shouldAuthenticateLdapRegularUser() {
        // Test LDAP user authentication
        ResponseEntity<Map> response = restTemplate
                .withBasicAuth("ldapuser", "password")
                .getForEntity("/api/ldap/users", Map.class);
                
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("user")).isEqualTo("ldapuser");
    }
    
    @Test
    void shouldDenyInvalidLdapCredentials() {
        // Test invalid credentials
        ResponseEntity<Map> response = restTemplate
                .withBasicAuth("invalid", "invalid")
                .getForEntity("/api/ldap/users", Map.class);
                
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
```

### **LDAP Connection Test**

```java
@Test
void shouldConnectToLdapServer() {
    LdapTemplate ldapTemplate = new LdapTemplate(contextSource());
    
    // Test LDAP connection
    List<String> users = ldapTemplate.search(
            "ou=people",
            "(objectclass=person)",
            (AttributesMapper<String>) attrs -> 
                    (String) attrs.get("uid").get()
    );
    
    assertThat(users).contains("ldapadmin", "ldapuser");
}
```

## 🔧 **Production LDAP Configuration**

### **Active Directory Integration**

```yaml
# application-production.yml
ldap:
  url: ldaps://ad.company.com:636
  base: dc=company,dc=com
  username: cn=service-account,ou=service-accounts,dc=company,dc=com
  password: ${LDAP_SERVICE_PASSWORD}
  user:
    search-base: ou=users
    search-filter: "(sAMAccountName={0})"
  group:
    search-base: ou=groups
    search-filter: "(member={0})"
    role-attribute: cn
```

### **SSL/TLS Configuration**

```java
@Bean
public ContextSource contextSource() {
    LdapContextSource context = new LdapContextSource();
    context.setUrl("ldaps://ldap.company.com:636");
    context.setBase("dc=company,dc=com");
    
    // SSL configuration
    context.setPooled(true);
    
    Map<String, Object> baseEnvironment = new HashMap<>();
    baseEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
    baseEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
    
    // Trust store configuration for SSL
    System.setProperty("javax.net.ssl.trustStore", "/path/to/truststore.jks");
    System.setProperty("javax.net.ssl.trustStorePassword", "password");
    
    context.setBaseEnvironmentProperties(baseEnvironment);
    context.afterPropertiesSet();
    
    return context;
}
```

## ⚡ **LDAP Best Practices**

### **✅ Do's**

1. **Use connection pooling** - Configure LDAP connection pools
2. **Implement SSL/TLS** - Secure LDAP communication (LDAPS)
3. **Use service accounts** - Dedicated accounts for LDAP binding
4. **Cache user details** - Cache LDAP lookups to reduce load
5. **Handle connection failures** - Implement retry logic and fallbacks

### **❌ Don'ts**

1. **Don't store LDAP passwords** in configuration files
2. **Don't ignore SSL certificate validation** in production
3. **Don't perform excessive LDAP searches** - optimize queries
4. **Don't hardcode LDAP DNs** - use configuration properties
5. **Don't forget timeout configuration** - set appropriate timeouts

### **🔧 Performance Optimization**

```java
@Bean
public LdapTemplate ldapTemplate() {
    LdapTemplate template = new LdapTemplate(contextSource());
    
    // Connection pool configuration
    template.setDefaultCountLimit(1000);
    template.setDefaultTimeLimit(5000);
    
    return template;
}

// Caching LDAP user details
@Cacheable("ldapUsers")
public UserDetails loadUserByUsername(String username) {
    return ldapUserDetailsService.loadUserByUsername(username);
}
```

## 🚀 **Next Steps**

- **[OAuth2 Authentication →](oauth2-auth.md)** - Social login integration
- **[JWT Tokens →](jwt-tokens.md)** - Stateless authentication
- **[SSO Integration →](sso-integration.md)** - Enterprise single sign-on
- **[API Reference →](../api/rest-endpoints.md)** - LDAP endpoints
- **[Security Configuration →](../security/common-security.md)** - LDAP security setup

---

**🏢 LDAP authentication provides enterprise-grade directory integration, enabling centralized user management and seamless integration with existing corporate infrastructure.**