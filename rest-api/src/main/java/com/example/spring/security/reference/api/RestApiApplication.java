package com.example.spring.security.reference.api;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * Main Spring Boot Application for the Spring Security Reference Project.
 * 
 * Educational Logging: This application demonstrates advanced Spring Security patterns
 * with comprehensive logging for learning authentication and authorization flows.
 * 
 * This application demonstrates:
 * - JWT and Session-based authentication
 * - Role-based authorization
 * - Multi-protocol security (REST, gRPC, WebSocket)
 * - Multiple authentication methods (JDBC, LDAP, OAuth2)
 * - Custom authentication providers and filters
 * - 2FA integration hooks
 */
@SpringBootApplication
@ComponentScan(basePackages = {
    "com.example.spring.security.reference.api",
    "com.example.spring.security.reference.commonauth",
    "com.example.spring.security.reference.jdbcauth",
    "com.example.spring.security.reference.ldapauth",
    "com.example.spring.security.reference.oauth2auth",
    "com.example.spring.security.reference.commonsecurity",
    "com.example.spring.security.reference.authorizationservice"
})
public class RestApiApplication {
    
    private static final Logger logger = LogManager.getLogger(RestApiApplication.class);

    public static void main(String[] args) {
        logger.info("🚀 [REST-API] Starting Spring Security Reference Application");
        logger.debug("📚 [LEARNING] This application demonstrates comprehensive Spring Security patterns");
        logger.debug("🔧 [REST-API] Component scan includes all authentication modules:");
        logger.debug("   • REST API endpoints");
        logger.debug("   • Common authentication utilities");
        logger.debug("   • JDBC authentication");
        logger.debug("   • LDAP authentication");
        logger.debug("   • OAuth2 authentication");
        logger.debug("   • Security configuration");
        logger.debug("   • Authorization service");
        
        SpringApplication.run(RestApiApplication.class, args);
        
        logger.info("✅ [REST-API] Spring Security Reference Application started successfully");
        logger.debug("🌐 [LEARNING] Application ready to demonstrate Spring Security authentication flows");
        logger.debug("📚 [REST-API] Available endpoints will be secured according to configuration");
    }
}