
package com.example.spring.security.reference.jdbcauth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Component;

/**
 * JDBC Data Initializer for demo users.
 * Educational Logging: Demonstrates how to initialize database users
 * with encrypted passwords for learning purposes.
 */
@Component
@Profile({"default", "jdbc-only"})
public class JdbcDataInitializer implements CommandLineRunner {
    private static final Logger logger = LogManager.getLogger(JdbcDataInitializer.class);

    @Autowired
    private JdbcUserDetailsManager jdbcUserDetailsManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        logger.info("🚀 [JDBC-DATA] Starting database user initialization");

        // Create demo admin user
        if (!jdbcUserDetailsManager.userExists("jdbcadmin")) {
            logger.info("👨‍💼 [JDBC-DATA] Creating admin user: jdbcadmin");
            UserDetails admin = User.builder()
                    .username("jdbcadmin")
                    .password(passwordEncoder.encode("password"))
                    .authorities("ROLE_ADMIN")
                    .build();
            jdbcUserDetailsManager.createUser(admin);
            logger.debug("✅ [JDBC-DATA] Admin user created with ROLE_ADMIN authority");
        } else {
            logger.debug("⚠️ [JDBC-DATA] Admin user 'jdbcadmin' already exists, skipping creation");
        }

        // Create demo regular user
        if (!jdbcUserDetailsManager.userExists("jdbcuser")) {
            logger.info("👤 [JDBC-DATA] Creating regular user: jdbcuser");
            UserDetails user = User.builder()
                    .username("jdbcuser")
                    .password(passwordEncoder.encode("password"))
                    .authorities("ROLE_USER")
                    .build();
            jdbcUserDetailsManager.createUser(user);
            logger.debug("✅ [JDBC-DATA] Regular user created with ROLE_USER authority");
        } else {
            logger.debug("⚠️ [JDBC-DATA] Regular user 'jdbcuser' already exists, skipping creation");
        }

        logger.info("🎉 [JDBC-DATA] Database initialization completed successfully");
        logger.info("📋 [JDBC-DATA] Available test credentials:");
        logger.info("   • jdbcadmin/password (ROLE_ADMIN)");
        logger.info("   • jdbcuser/password (ROLE_USER)");
        logger.debug("🔄 [LEARNING] These users can now authenticate through JDBC authentication provider");
    }
}