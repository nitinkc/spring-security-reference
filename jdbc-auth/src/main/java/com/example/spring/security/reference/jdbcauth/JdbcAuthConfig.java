
package com.example.spring.security.reference.jdbcauth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import javax.sql.DataSource;

/**
 * JDBC Authentication Configuration for Spring Security.
 * Educational Logging: This class demonstrates database-backed authentication
 * with comprehensive logging for learning Spring Security JDBC patterns.
 */
@Configuration
@Profile({"default", "jdbc-only"})
public class JdbcAuthConfig {
    private static final Logger logger = LogManager.getLogger(JdbcAuthConfig.class);

    @Autowired
    private DataSource dataSource;

    @Bean
    public PasswordEncoder passwordEncoder() {
        logger.info("🔐 [JDBC-AUTH] Creating BCrypt password encoder for database users");
        logger.debug("📚 [LEARNING] BCrypt adds salt and hashing for secure password storage");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JdbcUserDetailsManager jdbcUserDetailsManager() {
        logger.info("👥 [JDBC-AUTH] Creating JDBC UserDetailsManager with DataSource");
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
        manager.setUserExistsSql("SELECT username FROM users WHERE username = ?");
        manager.setUsersByUsernameQuery("SELECT username,password,enabled FROM users WHERE username = ?");
        manager.setAuthoritiesByUsernameQuery("SELECT username,authority FROM authorities WHERE username = ?");
        logger.debug("🔍 [JDBC-AUTH] Configured custom SQL queries for user lookup");
        return manager;
    }

    @Bean
    public DaoAuthenticationProvider jdbcAuthenticationProvider(JdbcUserDetailsManager jdbcUserDetailsManager, PasswordEncoder passwordEncoder) {
        logger.info("🏗️ [JDBC-AUTH] Creating DaoAuthenticationProvider for JDBC authentication");
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(jdbcUserDetailsManager);
        provider.setPasswordEncoder(passwordEncoder);
        logger.debug("✅ [JDBC-AUTH] Associated UserDetailsService and PasswordEncoder with provider");
        return provider;
    }
}