package com.example.spring.security.reference.commonsecurity;

import com.example.spring.security.reference.commonauth.CustomAuthenticationProvider;
import com.example.spring.security.reference.commonauth.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Enhanced Security Configuration supporting multiple authentication methods.
 * 
 * This configuration demonstrates:
 * - Multiple authentication providers (JWT, Custom, JDBC, LDAP, OAuth2)
 * - Profile-based configuration for different environments
 * - Flexible security filter chain supporting all authentication types
 * - Role-based authorization with multiple user sources
 */
@Configuration
@EnableWebSecurity
public class MultiAuthSecurityConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired(required = false)
    private DaoAuthenticationProvider jdbcAuthenticationProvider;

    @Autowired(required = false)
    private AuthenticationProvider ldapAuthenticationProvider;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

//    @Autowired(required = false)
//    private OAuth2UserService<?, OAuth2User> oauth2UserService;
//
//    @Autowired(required = false)
//    private OAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Default security configuration supporting all authentication methods
     */
    @Bean
    @Profile("!oauth2-only & !jdbc-only & !ldap-only")
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/api/public/**", "/api/auth/**").permitAll()
                // OAuth2 endpoints
                .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                // Admin endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // User endpoints  
                .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                // Auth-specific endpoints
                .requestMatchers("/api/jdbc/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/ldap/**").hasAnyRole("USER", "ADMIN")
                // Actuator endpoints
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()
            )
            // Add all authentication providers
            .authenticationProvider(customAuthenticationProvider);

        // Add JDBC provider if available
        if (jdbcAuthenticationProvider != null) {
            http.authenticationProvider(jdbcAuthenticationProvider);
        }

        // Add LDAP provider if available
        if (ldapAuthenticationProvider != null) {
            http.authenticationProvider(ldapAuthenticationProvider);
        }

//        // Configure OAuth2 if available
//        if (oauth2UserService != null) {
//            http.oauth2Login(oauth2 -> {
//                oauth2.userInfoEndpoint(userInfo -> userInfo.userService(oauth2UserService));
//                if (oauth2AuthenticationSuccessHandler != null) {
//                    oauth2.successHandler(oauth2AuthenticationSuccessHandler);
//                }
//            });
//        }

        // Add JWT filter
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * OAuth2-only configuration for OAuth2-focused environments
     */
    @Bean
    @Profile("oauth2-only")
    public SecurityFilterChain oauth2OnlyFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/login", "/oauth2/**", "/login/oauth2/**").permitAll()
                .anyRequest().authenticated()
            )
//            .oauth2Login(oauth2 -> {
//                if (oauth2UserService != null) {
//                    oauth2.userInfoEndpoint(userInfo -> userInfo.userService(oauth2UserService));
//                }
//                if (oauth2AuthenticationSuccessHandler != null) {
//                    oauth2.successHandler(oauth2AuthenticationSuccessHandler);
//                }
//            })
              ;

        return http.build();
    }

    /**
     * JDBC-only configuration for database-backed authentication
     */
    @Bean
    @Profile("jdbc-only")
    public SecurityFilterChain jdbcOnlyFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**", "/login", "/logout").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout.permitAll());

        if (jdbcAuthenticationProvider != null) {
            http.authenticationProvider(jdbcAuthenticationProvider);
        }

        return http.build();
    }

    /**
     * LDAP-only configuration for LDAP-backed authentication
     */
    @Bean
    @Profile("ldap-only")
    public SecurityFilterChain ldapOnlyFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**", "/login", "/logout").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout.permitAll());

        if (ldapAuthenticationProvider != null) {
            http.authenticationProvider(ldapAuthenticationProvider);
        }

        return http.build();
    }

    @Bean
    public GrpcSecurityInterceptor grpcSecurityInterceptor() {
        return new GrpcSecurityInterceptor();
    }

    @Bean  
    public WebSocketSecurityInterceptor webSocketSecurityInterceptor() {
        return new WebSocketSecurityInterceptor();
    }
}