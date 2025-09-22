

...existing code (starting from the first non-duplicate section)...

```java
// E-commerce Mobile App
@RestController
public class OrderController {
    @GetMapping("/api/orders")
    @PreAuthorize("hasRole('CUSTOMER')")
    public List<Order> getOrders(Authentication auth) {
        String userId = auth.getName();
        return orderService.findByUserId(userId);
    }
}

// Microservices Communication
@Component
public class PaymentServiceClient {
    public PaymentResult processPayment(String jwtToken, PaymentRequest request) {
        return webClient.post()
            .uri("/payment/process")
            .header("Authorization", "Bearer " + jwtToken)
            .bodyValue(request)
            .retrieve()
            .bodyToMono(PaymentResult.class)
            .block();
    }
}
```

---

### 2. Session-Based Authentication

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Traditional Web Applications**: Server-side rendered pages
- **Enterprise Intranets**: Internal company portals
- **Admin Dashboards**: CMS, analytics platforms
- **E-learning Platforms**: Course management systems
- **Banking Web Portals**: Where session security is critical

**❌ Not Suitable For:**
- **Mobile Applications**: No cookie support
- **Microservices**: Stateful, doesn't scale
- **Public APIs**: Not stateless
- **Cross-Domain Apps**: Cookie limitations

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (Cookie-based)
GraphQL: ✅ Excellent (Cookie-based)
gRPC: ❌ Not Suitable (No cookie support)
WebSocket: ✅ Excellent (Cookie upgrade)
SSE: ✅ Excellent (Cookie-based)
Webhooks: ❌ Not Applicable
WebRTC: ❌ Not Suitable
CoAP: ❌ Not Suitable
MQTT: ❌ Not Suitable
```

#### 🏢 **Real-World Examples**

```java
// E-commerce Admin Portal
@Controller
public class AdminController {
    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public String dashboard(Model model, HttpSession session) {
        String adminUser = (String) session.getAttribute("username");
        model.addAttribute("welcomeMessage", "Welcome " + adminUser);
        return "admin-dashboard";
    }
}

// Banking Web Portal with CSRF Protection
@Configuration
@EnableWebSecurity
public class BankingSecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                       .maximumSessions(1)
                       .maxSessionsPreventsLogin(true))
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .build();
    }
}
```

---

### 3. JDBC Database Authentication

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Small-Medium Business Applications**: CRM, inventory systems
- **Internal Corporate Tools**: HR systems, project management
- **Startup MVPs**: Quick user management setup
- **Legacy System Modernization**: Existing database integration
- **Departmental Applications**: Team-specific tools

**❌ Not Suitable For:**
- **High-Scale Consumer Apps**: Performance bottlenecks
- **Enterprise SSO Integration**: Use LDAP instead
- **Microservices**: Distributed auth complexity
- **Real-time Applications**: Database latency

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (Basic/Form auth)
GraphQL: ✅ Good (Basic auth)
gRPC: ✅ Moderate (Basic auth metadata)
WebSocket: ✅ Good (Initial handshake)
SSE: ✅ Good (Basic auth)
Webhooks: ⚠️ Limited (Receiving validation)
WebRTC: ❌ Not Suitable
CoAP: ✅ Moderate (Basic auth)
MQTT: ✅ Good (Username/password)
```

#### 🏢 **Real-World Examples**

```java
// Small Business CRM System
@RestController
public class CustomerController {
    @GetMapping("/api/customers")
    @PreAuthorize("hasRole('SALES_REP')")
    public List<Customer> getCustomers(Authentication auth) {
        String salesRep = auth.getName();
        return customerService.findByAssignedSalesRep(salesRep);
    }
}

// Inventory Management System
@Configuration
public class InventorySecurityConfig {
    @Bean
    public JdbcUserDetailsManager users(DataSource dataSource) {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
        
        // Custom queries for inventory-specific roles
        manager.setUsersByUsernameQuery(
            "SELECT username, password, enabled FROM inventory_users WHERE username = ?"
        );
        manager.setAuthoritiesByUsernameQuery(
            "SELECT u.username, r.role_name FROM inventory_users u " +
            "JOIN user_roles ur ON u.id = ur.user_id " +
            "JOIN roles r ON ur.role_id = r.id WHERE u.username = ?"
        );
        
        return manager;
    }
}
```

---

### 4. LDAP Authentication

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Enterprise Applications**: Large corporations with Active Directory
- **University Systems**: Student/faculty management
- **Government Applications**: Federal/state departments
- **Healthcare Systems**: Hospital management with AD integration
- **Financial Services**: Banks with existing LDAP infrastructure

**❌ Not Suitable For:**
- **Consumer Applications**: No LDAP infrastructure
- **Small Businesses**: Overkill for small teams
- **Mobile-First Apps**: Complex integration
- **Public APIs**: External users don't have LDAP

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (Basic auth with LDAP backend)
GraphQL: ✅ Good (LDAP authentication)
gRPC: ✅ Moderate (LDAP via interceptors)
WebSocket: ✅ Good (LDAP handshake)
SSE: ✅ Good (LDAP authentication)
Webhooks: ⚠️ Limited (Internal webhooks only)
WebRTC: ⚠️ Limited (Signaling auth)
CoAP: ⚠️ Limited (Custom LDAP integration)
MQTT: ⚠️ Moderate (LDAP username validation)
```

#### 🏢 **Real-World Examples**

```java
// Enterprise HR System
@RestController
public class EmployeeController {
    @GetMapping("/api/employees/{department}")
    @PreAuthorize("hasRole('HR_MANAGER') or hasRole('DEPARTMENT_HEAD')")
    public List<Employee> getDepartmentEmployees(@PathVariable String department, 
                                               Authentication auth) {
        // LDAP provides department information automatically
        LdapUserDetails userDetails = (LdapUserDetails) auth.getPrincipal();
        String userDepartment = userDetails.getDn().getValue("ou");
        
        if (hasRole("HR_MANAGER") || userDepartment.equals(department)) {
            return employeeService.findByDepartment(department);
        }
        throw new AccessDeniedException("Cannot access other departments");
    }
}

// University Course Management
@Configuration
public class UniversityLdapConfig {
    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://university-ad.edu:389");
        contextSource.setBase("dc=university,dc=edu");
        contextSource.setUserDn("cn=app-service,ou=services,dc=university,dc=edu");
        contextSource.setPassword("service-password");
        return contextSource;
    }
    
    @Bean
    public LdapAuthenticationProvider ldapAuthProvider() {
        return new LdapAuthenticationProvider(
            new BindAuthenticator(contextSource()),
            new DefaultLdapAuthoritiesPopulator(contextSource(), "ou=groups")
        );
    }
}
```

---

### 5. OAuth2 / Social Login

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Consumer Applications**: Social media apps, games
- **B2C E-commerce**: Customer-facing online stores
- **Content Platforms**: Blogs, forums, media sites
- **Developer Tools**: GitHub integration, API platforms
- **Third-Party Integrations**: Apps connecting to Google/Microsoft

**❌ Not Suitable For:**
- **High-Security Applications**: Military, banking core systems
- **Air-Gapped Systems**: No internet connectivity
- **Simple Internal Tools**: Overkill for basic auth
- **Legacy Enterprise**: May not support external OAuth

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (Standard OAuth2 flows)
GraphQL: ✅ Excellent (Bearer tokens)
gRPC: ✅ Good (OAuth2 tokens in metadata)
WebSocket: ✅ Good (OAuth2 token in upgrade)
SSE: ✅ Good (OAuth2 in headers)
Webhooks: ✅ Excellent (OAuth2 for callback auth)
WebRTC: ⚠️ Moderate (OAuth2 for signaling)
CoAP: ⚠️ Limited (Custom OAuth2 implementation)
MQTT: ⚠️ Limited (OAuth2 tokens as passwords)
```

#### 🏢 **Real-World Examples**

```java
// Social Media Platform
@RestController
public class SocialController {
    @GetMapping("/api/profile")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public UserProfile getProfile(OAuth2Authentication auth) {
        OAuth2AuthenticationDetails details = 
            (OAuth2AuthenticationDetails) auth.getDetails();
        String socialId = (String) details.getDecodedDetails().get("sub");
        
        return profileService.findBySocialId(socialId);
    }
}

// E-commerce with Google Pay Integration
@RestController
public class CheckoutController {
    @PostMapping("/api/checkout/google-pay")
    public PaymentResult processGooglePay(@RequestBody GooglePayRequest request,
                                        OAuth2Authentication auth) {
        // Verify Google OAuth2 token has payment scope
        if (!auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("SCOPE_payments"))) {
            throw new InsufficientScopeException("Payment scope required");
        }
        
        return googlePayService.processPayment(request);
    }
}

// Developer API Platform
@Configuration
@EnableOAuth2ResourceServer
public class ApiPlatformConfig {
    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
        return http
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder()))
                .accessDeniedHandler(new OAuth2AccessDeniedHandler())
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasAuthority("SCOPE_admin")
                .requestMatchers("/api/user/**").hasAuthority("SCOPE_user")
                .anyRequest().authenticated()
            )
            .build();
    }
}
```

---

### 6. API Keys

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Public APIs**: Weather, maps, payment gateways
- **IoT Devices**: Sensors, smart home devices
- **Batch Processing**: Data pipelines, ETL jobs
- **Service Monitoring**: Health checks, metrics collection
- **Third-Party Integrations**: External service connections

**❌ Not Suitable For:**
- **User-Facing Applications**: No user identity
- **High-Security Transactions**: Insufficient security
- **Complex Authorization**: No role-based access
- **Session Management**: Stateless only

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (Header/query param)
GraphQL: ✅ Excellent (Header-based)
gRPC: ✅ Excellent (Metadata headers)
WebSocket: ✅ Good (Connection headers)
SSE: ✅ Good (Query parameters)
Webhooks: ✅ Excellent (Signature verification)
WebRTC: ⚠️ Limited (Signaling auth only)
CoAP: ✅ Excellent (Custom headers)
MQTT: ✅ Good (Username field)
```

#### 🏢 **Real-World Examples**

```java
// Weather API Service
@RestController
public class WeatherController {
    @GetMapping("/api/weather/{city}")
    public WeatherData getWeather(@PathVariable String city,
                                 @RequestHeader("X-API-Key") String apiKey) {
        if (!apiKeyService.isValid(apiKey)) {
            throw new UnauthorizedException("Invalid API key");
        }
        
        ApiKeyInfo keyInfo = apiKeyService.getKeyInfo(apiKey);
        if (keyInfo.hasExceededRateLimit()) {
            throw new RateLimitExceededException("Rate limit exceeded");
        }
        
        return weatherService.getWeatherData(city);
    }
}

// IoT Device Communication
@Component
public class IoTDeviceAuthFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        String deviceId = httpRequest.getHeader("X-Device-ID");
        String apiKey = httpRequest.getHeader("X-Device-Key");
        
        if (deviceAuthService.validateDevice(deviceId, apiKey)) {
            // Create device-specific security context
            DeviceAuthentication auth = new DeviceAuthentication(deviceId);
            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(request, response);
        } else {
            ((HttpServletResponse) response).setStatus(HttpStatus.UNAUTHORIZED.value());
        }
    }
}

// Webhook Signature Verification
@RestController
public class WebhookController {
    @PostMapping("/webhooks/payment")
    public ResponseEntity<String> handlePaymentWebhook(
            @RequestBody String payload,
            @RequestHeader("X-Signature") String signature,
            @RequestHeader("X-API-Key") String apiKey) {
        
        if (!webhookService.verifySignature(payload, signature, apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid signature");
        }
        
        paymentService.processWebhookEvent(payload);
        return ResponseEntity.ok("Processed");
    }
}
```

---

### 7. mTLS (Mutual TLS)

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Banking & Financial Services**: Core banking systems
- **Healthcare Systems**: HIPAA-compliant applications
- **Government & Military**: Classified system communications
- **B2B Enterprise Integration**: Secure partner APIs
- **Microservices in Zero-Trust Architecture**: Service mesh security

**❌ Not Suitable For:**
- **Public Consumer APIs**: Certificate management complexity
- **Mobile Applications**: Certificate distribution challenges
- **Development/Testing**: Too complex for rapid iteration
- **Small-Scale Applications**: Operational overhead

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (HTTPS with client certs)
GraphQL: ✅ Excellent (HTTPS with client certs)
gRPC: ✅ Excellent (Native TLS support)
WebSocket: ✅ Good (WSS with client certs)
SSE: ✅ Good (HTTPS with client certs)
Webhooks: ✅ Excellent (Mutual verification)
WebRTC: ✅ Good (DTLS for data channels)
CoAP: ✅ Good (DTLS support)
MQTT: ✅ Good (TLS with client certs)
```

#### 🏢 **Real-World Examples**

```java
// Banking Core System
@Configuration
@EnableWebSecurity
public class BankingSecurityConfig {
    @Bean
    public SecurityFilterChain mtlsFilterChain(HttpSecurity http) throws Exception {
        return http
            .requiresChannel(channel -> 
                channel.requestMatchers("/api/banking/**").requiresSecure())
            .x509(x509 -> x509
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(bankingX509UserDetailsService())
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/banking/transfer").hasRole("BANKING_SYSTEM")
                .requestMatchers("/api/banking/balance").hasRole("ACCOUNT_SERVICE")
                .anyRequest().denyAll()
            )
            .build();
    }
    
    @Bean
    public X509UserDetailsService bankingX509UserDetailsService() {
        return new X509UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) {
                // Username extracted from certificate CN
                if ("core-banking-service".equals(username)) {
                    return User.withUsername(username)
                        .password("") // Not used for certificate auth
                        .authorities("ROLE_BANKING_SYSTEM")
                        .build();
                }
                throw new UsernameNotFoundException("Unknown service: " + username);
            }
        };
    }
}

// Healthcare HIPAA-Compliant API
@RestController
public class PatientController {
    @GetMapping("/api/patients/{patientId}")
    @PreAuthorize("hasRole('HEALTHCARE_PROVIDER')")
    public PatientRecord getPatientRecord(@PathVariable String patientId,
                                        X509Authentication auth) {
        X509Certificate clientCert = auth.getCredentials();
        String organizationUnit = getOrganizationUnit(clientCert);
        
        // Verify the requesting system is authorized for this patient
        if (!patientAuthService.canAccess(organizationUnit, patientId)) {
            throw new AccessDeniedException("Unauthorized patient access");
        }
        
        return patientService.getPatientRecord(patientId);
    }
}

// Microservices Service Mesh Communication
@Component
public class ServiceMeshClient {
    private final WebClient webClient;
    
    public ServiceMeshClient() {
        SslContext sslContext = SslContextBuilder.forClient()
            .keyManager(getClientCertificate(), getClientPrivateKey())
            .trustManager(getTrustedCertificates())
            .build();
            
        HttpClient httpClient = HttpClient.create()
            .secure(sslSpec -> sslSpec.sslContext(sslContext));
            
        this.webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(httpClient))
            .build();
    }
    
    public Mono<OrderResponse> callOrderService(OrderRequest request) {
        return webClient.post()
            .uri("https://order-service:8443/api/orders")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(OrderResponse.class);
    }
}
```

---

### 8. Custom Token Authentication

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Gaming Platforms**: Session tokens, achievement systems
- **Proprietary Protocols**: Custom B2B integrations
- **Legacy System Integration**: Non-standard authentication
- **High-Performance Systems**: Optimized token formats
- **Specialized Industries**: Unique compliance requirements

**❌ Not Suitable For:**
- **Standard Web Applications**: Use established standards
- **Interoperability Requirements**: Stick to OAuth2/JWT
- **Small Development Teams**: Maintenance overhead
- **Audit/Compliance Heavy**: Standards preferred

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (Custom headers)
GraphQL: ✅ Excellent (Custom headers)
gRPC: ✅ Excellent (Custom metadata)
WebSocket: ✅ Excellent (Custom protocols)
SSE: ✅ Good (Custom headers)
Webhooks: ✅ Good (Custom signatures)
WebRTC: ✅ Good (Custom signaling)
CoAP: ✅ Excellent (Custom options)
MQTT: ✅ Good (Custom auth fields)
```

#### 🏢 **Real-World Examples**

```java
// Gaming Platform with Custom Session Tokens
@RestController
public class GameController {
    @PostMapping("/api/game/action")
    public GameActionResult performAction(@RequestBody GameAction action,
                                        @RequestHeader("X-Game-Token") String gameToken) {
        GameSession session = gameTokenService.validateAndRefresh(gameToken);
        
        if (session.hasExpired()) {
            throw new GameSessionExpiredException("Session expired, please rejoin");
        }
        
        if (!session.getPlayer().canPerformAction(action.getType())) {
            throw new InsufficientPermissionsException("Action not allowed");
        }
        
        return gameEngine.processAction(session.getPlayerId(), action);
    }
}

// High-Performance Trading System
@Component
public class TradingAuthFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        String tradingToken = httpRequest.getHeader("X-Trading-Token");
        if (tradingToken != null) {
            // Custom token format: TRADER_ID|TIMESTAMP|SIGNATURE
            TradingCredentials creds = tradingTokenService.parseToken(tradingToken);
            
            if (tradingTokenService.isValidSignature(creds) && 
                creds.getTimestamp() > (System.currentTimeMillis() - 30000)) { // 30s expiry
                
                TradingAuthentication auth = new TradingAuthentication(
                    creds.getTraderId(), 
                    creds.getPermissions()
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
                chain.doFilter(request, response);
                return;
            }
        }
        
        ((HttpServletResponse) response).setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}

// Legacy System Integration
@Service
public class LegacySystemAdapter {
    public void authenticateWithLegacySystem(String customToken) {
        // Parse proprietary token format
        LegacyTokenData tokenData = legacyTokenParser.parse(customToken);
        
        // Validate with legacy authentication service
        if (legacyAuthService.validateToken(tokenData)) {
            // Convert to Spring Security authentication
            LegacyAuthentication auth = new LegacyAuthentication(
                tokenData.getUserId(),
                tokenData.getDepartment(),
                tokenData.getRoles()
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
    }
}
```

---

### 9. SAML (Security Assertion Markup Language)

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Enterprise Single Sign-On**: Large organizations with existing SAML infrastructure
- **Educational Institutions**: University systems with federated identity
- **Government Applications**: Inter-agency authentication
- **Healthcare Networks**: Hospital system integration
- **B2B Partner Integration**: Secure partner access

**❌ Not Suitable For:**
- **Mobile Applications**: XML overhead, complexity
- **Modern Web APIs**: REST/JSON preferred
- **Small Organizations**: Setup complexity
- **Real-time Applications**: XML processing overhead

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Good (SAML assertions for auth)
GraphQL: ✅ Moderate (SAML session-based)
gRPC: ❌ Not Suitable (XML overhead)
WebSocket: ⚠️ Limited (Initial SAML handshake)
SSE: ⚠️ Limited (Session-based only)
Webhooks: ❌ Not Applicable
WebRTC: ❌ Not Suitable
CoAP: ❌ Not Suitable
MQTT: ❌ Not Suitable
```

#### 🏢 **Real-World Examples**

```java
// Enterprise Portal with SAML SSO
@Configuration
@EnableWebSecurity
public class EnterprisePortalConfig {
    @Bean
    public SecurityFilterChain samlFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/saml/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> saml2
                .relyingPartyRegistrationRepository(relyingPartyRegistrations())
                .userDetailsService(samlUserDetailsService())
            )
            .saml2Logout(saml2 -> saml2
                .logoutRequest(request -> request
                    .logoutUrl("/saml2/logout")
                )
                .logoutResponse(response -> response
                    .logoutUrl("/saml2/logout")
                )
            )
            .build();
    }
    
    @Bean
    public UserDetailsService samlUserDetailsService() {
        return new Saml2UserDetailsService() {
            @Override
            public UserDetails loadUserBySaml2User(Saml2User saml2User) {
                String email = saml2User.getAttribute("email");
                String department = saml2User.getAttribute("department");
                List<String> roles = saml2User.getAttribute("roles");
                
                return User.withUsername(email)
                    .password("") // Not used for SAML
                    .authorities(roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList()))
                    .build();
            }
        };
    }
}

// University System with Federated Identity
@RestController
public class AcademicController {
    @GetMapping("/api/courses/enrolled")
    @PreAuthorize("hasRole('STUDENT') or hasRole('FACULTY')")
    public List<Course> getEnrolledCourses(Authentication auth) {
        Saml2AuthenticatedPrincipal principal = 
            (Saml2AuthenticatedPrincipal) auth.getPrincipal();
            
        String studentId = principal.getAttribute("studentId");
        String university = principal.getAttribute("institution");
        
        // Cross-university enrollment support
        return courseService.findEnrollments(studentId, university);
    }
}

// Healthcare Network Integration
@Service
public class HealthcareNetworkService {
    public PatientData getPatientFromPartnerHospital(String patientId, 
                                                   Saml2Authentication samlAuth) {
        Saml2AuthenticatedPrincipal principal = samlAuth.getPrincipal();
        
        String requestingHospital = principal.getAttribute("organization");
        String physicianLicense = principal.getAttribute("licenseNumber");
        
        // Verify inter-hospital data sharing agreements
        if (!dataSharingService.isAuthorized(requestingHospital, physicianLicense)) {
            throw new AccessDeniedException("No data sharing agreement");
        }
        
        return partnerHospitalClient.getPatientData(patientId, samlAuth);
    }
}
```

---

### 10. Cross-Application SSO (Single Sign-On)

#### 🏭 **Industry Use Cases**

**✅ Best For:**
- **Corporate Application Suites**: Office 365, Google Workspace alternatives
- **Educational Platforms**: Student portals accessing multiple university systems
- **Healthcare Networks**: EMR systems with multiple integrated applications
- **E-commerce Ecosystems**: Main site + blog + support + admin portals
- **Multi-Tenant SaaS Platforms**: Different applications under single tenant

**❌ Not Suitable For:**
- **Single Application Systems**: No multiple apps to integrate
- **Highly Isolated Systems**: Security requires separate authentication
- **Different Security Domains**: Cross-organization without federation
- **Legacy Systems**: May not support modern SSO protocols

#### 📡 **API Protocol Support**

```yaml
REST APIs: ✅ Excellent (Session/JWT sharing)
GraphQL: ✅ Excellent (Same auth context)
gRPC: ✅ Good (JWT token propagation)
WebSocket: ✅ Good (Session-based SSO)
SSE: ✅ Good (Session-based SSO)
Webhooks: ⚠️ Limited (Cross-app notifications)
WebRTC: ⚠️ Moderate (Signaling auth sharing)
CoAP: ⚠️ Limited (Custom SSO implementation)
MQTT: ⚠️ Limited (Shared credentials)
```

#### 🏢 **Real-World Examples**

```java
// Corporate Application Suite SSO
@RestController
public class SSOController {
    
    @PostMapping("/sso/authenticate")
    public ResponseEntity<SSOTokenResponse> authenticateForSSO(
            @RequestBody SSOLoginRequest request) {
        
        // Authenticate user with primary method (LDAP/OAuth2)
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        
        if (auth.isAuthenticated()) {
            // Generate SSO token for cross-application use
            SSOToken ssoToken = ssoTokenService.generateSSOToken(auth);
            
            // Store in distributed session store (Redis/Hazelcast)
            distributedSessionStore.put(ssoToken.getSessionId(), auth);
            
            return ResponseEntity.ok(new SSOTokenResponse(
                ssoToken.getToken(),
                ssoToken.getExpiryTime(),
                getAuthorizedApplications(auth)
            ));
        }
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}

// Multi-Application Authentication Filter
@Component
public class SSOAuthenticationFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        
        String ssoToken = extractSSOToken(request);
        
        if (ssoToken != null) {
            try {
                // Validate SSO token with central SSO service
                SSOValidationResponse validation = ssoService.validateToken(ssoToken, getCurrentApplicationId());
                
                if (validation.isValid()) {
                    // Create authentication context for this application
                    Collection<SimpleGrantedAuthority> authorities = validation.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());
                        
                    SSOAuthentication auth = new SSOAuthentication(
                        validation.getUsername(),
                        authorities,
                        ssoToken
                    );
                    
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception e) {
                log.debug("SSO authentication failed", e);
                // Fall back to regular authentication methods
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
```

---

## 🔄 Protocol-Specific Security Patterns

### REST APIs
```java
// Multi-auth support for different client types
@Configuration
public class RestApiSecurityConfig {
    @Bean
    public SecurityFilterChain restFilterChain(HttpSecurity http) throws Exception {
        return http
            .securityMatchers(matchers -> matchers
                .requestMatchers("/api/**"))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/mobile/**").hasAuthority("SCOPE_mobile")  // OAuth2
                .requestMatchers("/api/admin/**").hasRole("ADMIN")               // Session/JWT
                .requestMatchers("/api/partner/**").hasRole("PARTNER_SYSTEM")    // mTLS
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .build();
    }
}
```

### GraphQL
```java
@Component
public class GraphQLSecurityConfig {
    @EventListener
    public void configureGraphQLSecurity(GraphQLServletListener.RequestCallback callback) {
        callback.addDataFetcherExceptionResolver((ex, env) -> {
            if (ex instanceof AccessDeniedException) {
                return DataFetcherExceptionResolverAdapter
                    .createResult("Access denied: " + ex.getMessage());
            }
            return null;
        });
    }
}

@Component
public class GraphQLAuthDirective implements SchemaDirectiveWiring {
    @Override
    public GraphQLFieldDefinition onField(SchemaDirectiveWiringEnvironment<GraphQLFieldDefinition> env) {
        String requiredRole = env.getDirective().getArgument("role").getValue();
        
        DataFetcher<?> originalDataFetcher = env.getCodeRegistry()
            .getDataFetcher(env.getFieldsContainer(), env.getFieldDefinition());
            
        DataFetcher<?> authDataFetcher = (fetcherEnv) -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_" + requiredRole))) {
                throw new AccessDeniedException("Insufficient privileges");
            }
            return originalDataFetcher.get(fetcherEnv);
        };
        
        env.getCodeRegistry().dataFetcher(env.getFieldsContainer(), 
                                        env.getFieldDefinition(), authDataFetcher);
        return env.getElement();
    }
}
```

### gRPC
```java
@Component
public class GrpcSecurityInterceptor implements ServerInterceptor {
    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        
        String authorization = headers.get(Metadata.Key.of("Authorization", ASCII_STRING_MARSHALLER));
        
        try {
            Authentication auth = null;
            
            if (authorization != null) {
                if (authorization.startsWith("Bearer ")) {
                    // JWT Token
                    String token = authorization.substring(7);
                    auth = jwtAuthenticationProvider.authenticate(
                        new JwtAuthenticationToken(token));
                } else if (authorization.startsWith("Basic ")) {
                    // Basic Auth (LDAP/JDBC)
                    auth = basicAuthenticationProvider.authenticate(
                        parseBasicAuth(authorization));
                }
            }
            
            if (auth != null && auth.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(auth);
                return next.startCall(call, headers);
            }
            
        } catch (Exception e) {
            call.close(Status.UNAUTHENTICATED.withDescription("Authentication failed"), new Metadata());
            return new ServerCall.Listener<ReqT>() {};
        }
        
        call.close(Status.UNAUTHENTICATED.withDescription("Missing authentication"), new Metadata());
        return new ServerCall.Listener<ReqT>() {};
    }
}
```

### WebSocket
```java
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketSecurityConfig implements WebSocketMessageBrokerConfigurer {
    
    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(new ChannelInterceptor() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                StompHeaderAccessor accessor = 
                    MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
                
                if (StompCommand.CONNECT.equals(accessor.getCommand())) {
                    String token = accessor.getFirstNativeHeader("Authorization");
                    if (token != null && token.startsWith("Bearer ")) {
                        try {
                            Authentication auth = jwtAuthenticationProvider
                                .authenticate(new JwtAuthenticationToken(token.substring(7)));
                            accessor.setUser(auth);
                            SecurityContextHolder.getContext().setAuthentication(auth);
                        } catch (Exception e) {
                            throw new MessagingException("Authentication failed");
                        }
                    } else {
                        throw new MessagingException("Missing authentication token");
                    }
                }
                return message;
            }
        });
    }
    
    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic", "/queue");
        config.setApplicationDestinationPrefixes("/app");
        config.setUserDestinationPrefix("/user");
    }
}
```

### Server-Sent Events (SSE)
```java
@RestController
public class SSEController {
    
    @GetMapping(value = "/api/notifications/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @PreAuthorize("hasRole('USER')")
    public SseEmitter streamNotifications(Authentication auth) {
        String userId = auth.getName();
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        
        // Register user-specific SSE connection
        notificationService.registerSSEConnection(userId, emitter);
        
        emitter.onCompletion(() -> notificationService.removeSSEConnection(userId));
        emitter.onTimeout(() -> notificationService.removeSSEConnection(userId));
        
        return emitter;
    }
    
    // Send authenticated notifications
    @PostMapping("/api/notifications/send")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> sendNotification(@RequestBody NotificationRequest request) {
        notificationService.sendToUser(request.getUserId(), request.getMessage());
        return ResponseEntity.ok().build();
    }
}
```

### Webhooks
```java
@RestController
public class WebhookController {
    
    // Incoming webhook with signature verification
    @PostMapping("/webhooks/payment/{provider}")
    public ResponseEntity<String> handlePaymentWebhook(
            @PathVariable String provider,
            @RequestBody String payload,
            @RequestHeader("X-Signature") String signature,
            HttpServletRequest request) {
        
        WebhookProvider webhookProvider = webhookProviderService.getProvider(provider);
        
        if (!webhookProvider.verifySignature(payload, signature)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid signature");
        }
        
        paymentProcessor.processWebhookEvent(provider, payload);
        return ResponseEntity.ok("Processed");
    }
    
    // Outgoing webhook with OAuth2
    @EventListener
    public void sendWebhookNotification(OrderCompletedEvent event) {
        String webhookUrl = customerService.getWebhookUrl(event.getCustomerId());
        String accessToken = oAuth2TokenService.getClientToken("webhook-sender");
        
        WebClient.create()
            .post()
            .uri(webhookUrl)
            .header("Authorization", "Bearer " + accessToken)
            .header("X-Event-Type", "order.completed")
            .bodyValue(event.getOrderData())
            .retrieve()
            .toBodilessEntity()
            .subscribe(
                success -> log.info("Webhook sent successfully"),
                error -> log.error("Webhook failed", error)
            );
    }
}
```

---

## 🎯 Decision Framework

### Choose Your Security Method:

#### 1. **Start with these questions:**
- **Who are your users?** (Internal employees → LDAP, External consumers → OAuth2)
- **What's your scale?** (Small → JDBC/Session, Large → JWT/OAuth2)
- **What's your risk level?** (High → mTLS, Medium → JWT, Low → API Keys)
- **What protocols do you use?** (REST → Any, gRPC → JWT/mTLS, WebSocket → JWT)

#### 2. **Common combinations:**
- **Enterprise Web App**: Session + LDAP
- **Mobile App**: JWT + OAuth2
- **Microservices**: JWT + mTLS
- **Public API**: API Keys + Rate Limiting
- **B2B Integration**: mTLS + Custom Tokens
- **Government/Healthcare**: SAML + mTLS

#### 3. **Migration paths:**
- **Start Simple**: JDBC → LDAP → OAuth2
- **Scale Up**: Session → JWT → OAuth2
- **Secure Up**: API Keys → JWT → mTLS

---

**🔍 Each authentication method in this project demonstrates these patterns with working code examples, theory, and integration guides!**