package com.example.restapi;

import com.example.commonauth.JwtTokenUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * REST API Controller with comprehensive Spring Security demonstrations.
 * 
 * Educational Logging: This controller demonstrates various secured endpoints
 * with comprehensive logging for learning Spring Security REST API patterns.
 * 
 * This controller demonstrates:
 * - Public endpoints (no authentication required)
 * - Role-based access control with different authentication sources
 * - Authentication method detection and user information extraction
 * - JWT token generation for various authentication types
 * - Comprehensive logging of security context and user details
 */
@RestController
public class ApiController {
    
    private static final Logger logger = LogManager.getLogger(ApiController.class);

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    public ApiController() {
        logger.info("🌐 [REST-API] Initializing API Controller");
        logger.debug("📚 [LEARNING] This controller demonstrates secured REST endpoints");
    }

    @GetMapping("/api/public/hello")
    public String publicHello() {
        logger.info("👋 [REST-API] Public hello endpoint accessed");
        logger.debug("📚 [LEARNING] This endpoint requires no authentication");
        return "Hello, world! (public endpoint - no authentication required)";
    }

    @GetMapping("/api/admin/secure")
    public Map<String, Object> adminSecure() {
        logger.info("👨‍💼 [REST-API] Admin secure endpoint accessed");
        logger.debug("📚 [LEARNING] This endpoint requires ROLE_ADMIN authority");
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String authType = determineAuthType(auth);
        
        logger.debug("🔒 [REST-API] Admin endpoint authentication details:");
        logger.debug("   • User: {}", auth.getName());
        logger.debug("   • Auth Type: {}", authType);
        logger.debug("   • Authorities: {}", auth.getAuthorities());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Hello, Admin! (secured endpoint)");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("authType", authType);
        
        logger.debug("✅ [REST-API] Admin endpoint response prepared");
        return response;
    }

    @GetMapping("/api/user/secure")
    public Map<String, Object> userSecure() {
        logger.info("👤 [REST-API] User secure endpoint accessed");
        logger.debug("📚 [LEARNING] This endpoint requires ROLE_USER or ROLE_ADMIN authority");
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String authType = determineAuthType(auth);
        
        logger.debug("🔒 [REST-API] User endpoint authentication details:");
        logger.debug("   • User: {}", auth.getName());
        logger.debug("   • Auth Type: {}", authType);
        logger.debug("   • Authorities: {}", auth.getAuthorities());
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Hello, User! (secured endpoint)");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("authType", authType);
        
        logger.debug("✅ [REST-API] User endpoint response prepared");
        return response;
    }

    @PostMapping("/api/auth/login")
    public Map<String, Object> login(@RequestParam String username, @RequestParam String password) {
        logger.info("🔐 [REST-API] Login endpoint accessed for user: {}", username);
        logger.debug("📚 [LEARNING] This endpoint generates JWT tokens for API access");
        
        // Basic JWT token generation (replace with real authentication logic)
        String role = determineUserRole(username);
        String token = jwtTokenUtil.generateToken(username, role);
        
        logger.debug("🎟️ [REST-API] JWT token generated for user:");
        logger.debug("   • Username: {}", username);
        logger.debug("   • Role: {}", role);
        logger.debug("   • Token prefix: {}...", token.substring(0, Math.min(10, token.length())));
        logger.debug("📚 [LEARNING] JWT contains encoded user identity and role claims");
        
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("username", username);
        response.put("role", role);
        response.put("message", "Login successful - use this JWT token for authenticated requests");
        response.put("usage", "Add header: Authorization: Bearer " + token);
        
        logger.debug("✅ [REST-API] Login response prepared with JWT token");
        return response;
    }

    @GetMapping("/api/jdbc/users")
    public Map<String, Object> jdbcUsers() {
        logger.info("🗄️ [REST-API] JDBC authentication demo endpoint accessed");
        logger.debug("📚 [LEARNING] This endpoint demonstrates JDBC database authentication");
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        logger.debug("🔒 [REST-API] JDBC endpoint authentication:");
        logger.debug("   • User: {}", auth.getName());
        logger.debug("   • Auth Type: {}", determineAuthType(auth));
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "JDBC Authentication Demo");
        response.put("user", auth.getName());
        response.put("credentials", Map.of(
            "jdbcadmin", "password (ROLE_ADMIN)",
            "jdbcuser", "password (ROLE_USER)"
        ));
        
        logger.debug("✅ [REST-API] JDBC demo response prepared");
        return response;
    }

    @GetMapping("/api/ldap/users")  
    public Map<String, Object> ldapUsers() {
        logger.info("🏢 [REST-API] LDAP authentication demo endpoint accessed");
        logger.debug("📚 [LEARNING] This endpoint demonstrates LDAP directory authentication");
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        logger.debug("🔒 [REST-API] LDAP endpoint authentication:");
        logger.debug("   • User: {}", auth.getName());
        logger.debug("   • Auth Type: {}", determineAuthType(auth));
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "LDAP Authentication Demo");
        response.put("user", auth.getName());
        response.put("credentials", Map.of(
            "ldapadmin", "password (ROLE_ADMIN)",
            "ldapuser", "password (ROLE_USER)"
        ));
        
        logger.debug("✅ [REST-API] LDAP demo response prepared");
        return response;
    }

    @GetMapping("/api/oauth2/profile")
    public Map<String, Object> oauth2Profile() {
        logger.info("🌐 [REST-API] OAuth2 profile endpoint accessed");
        logger.debug("📚 [LEARNING] This endpoint demonstrates OAuth2/OIDC authentication");
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> response = new HashMap<>();
        response.put("message", "OAuth2 Authentication Demo");
        
        if (auth.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) auth.getPrincipal();
            logger.debug("🔒 [REST-API] OAuth2 user details:");
            logger.debug("   • Name: {}", oauth2User.getName());
            logger.debug("   • Email: {}", oauth2User.getAttribute("email"));
            logger.debug("   • Attributes: {}", oauth2User.getAttributes().keySet());
            logger.debug("📚 [LEARNING] OAuth2 user has provider-specific attributes");
            
            response.put("user", oauth2User.getName());
            response.put("email", oauth2User.getAttribute("email"));
            response.put("provider", "OAuth2");
            response.put("attributes", oauth2User.getAttributes());
        } else {
            logger.debug("🔒 [REST-API] Non-OAuth2 user in OAuth2 endpoint:");
            logger.debug("   • User: {}", auth.getName());
            logger.debug("   • Authorities: {}", auth.getAuthorities());
            
            response.put("user", auth.getName());
            response.put("authorities", auth.getAuthorities());
        }
        
        logger.debug("✅ [REST-API] OAuth2 profile response prepared");
        return response;
    }

    @GetMapping("/api/auth/info")
    public Map<String, Object> authInfo() {
        logger.info("ℹ️ [REST-API] Authentication info endpoint accessed");
        logger.debug("📚 [LEARNING] This endpoint provides current authentication details");
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String authType = determineAuthType(auth);
        
        logger.debug("🔍 [REST-API] Current authentication state:");
        logger.debug("   • Authenticated: {}", auth.isAuthenticated());
        logger.debug("   • Username: {}", auth.getName());
        logger.debug("   • Auth Type: {}", authType);
        logger.debug("   • Principal Type: {}", auth.getPrincipal().getClass().getSimpleName());
        logger.debug("   • Authorities: {}", auth.getAuthorities());
        
        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", auth.isAuthenticated());
        response.put("username", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("authType", authType);
        response.put("principalType", auth.getPrincipal().getClass().getSimpleName());
        
        logger.debug("✅ [REST-API] Authentication info response prepared");
        return response;
    }

    private String determineAuthType(Authentication auth) {
        if (auth == null) {
            logger.debug("🔍 [REST-API] Authentication is null");
            return "None";
        }
        
        String principalType = auth.getPrincipal().getClass().getSimpleName();
        logger.debug("🔍 [REST-API] Determining auth type from principal: {}", principalType);
        
        String authType;
        if (principalType.contains("OAuth2")) {
            authType = "OAuth2";
        } else if (principalType.contains("Ldap")) {
            authType = "LDAP";
        } else if (principalType.contains("User")) {
            authType = "JDBC/Database";
        } else if (auth.getDetails() != null && auth.getDetails().toString().contains("JWT")) {
            authType = "JWT";
        } else {
            authType = "Custom/Session";
        }
        
        logger.debug("🏷️ [REST-API] Determined auth type: {}", authType);
        return authType;
    }

    private String determineUserRole(String username) {
        logger.debug("🔍 [REST-API] Determining role for username: {}", username);
        
        String role;
        // Simple role determination logic for demo
        if ("admin".equals(username) || username.contains("admin")) {
            role = "ROLE_ADMIN";
        } else {
            role = "ROLE_USER";
        }
        
        logger.debug("🏷️ [REST-API] Determined role: {}", role);
        logger.debug("📚 [LEARNING] Role assignment based on username pattern (demo logic)");
        return role;
    }
}