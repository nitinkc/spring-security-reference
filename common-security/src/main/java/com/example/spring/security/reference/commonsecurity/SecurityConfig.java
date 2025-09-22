package com.example.spring.security.reference.commonsecurity;

import com.example.spring.security.reference.commonauth.CustomAuthenticationProvider;
import com.example.spring.security.reference.commonauth.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security configuration for the reference project.
 * 
 * This configuration demonstrates:
 * - JWT authentication filter integration
 * - Custom authentication provider setup
 * - Role-based authorization rules
 * - Multi-protocol security setup (REST, gRPC, WebSocket)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Disable CSRF for API usage
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/api/public/**", "/api/auth/login").permitAll()
                // Admin endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // User endpoints  
                .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                // Actuator endpoints (for health checks)
                .requestMatchers("/actuator/health").permitAll()
                // All other requests need authentication
                .anyRequest().authenticated()
            )
            .authenticationProvider(customAuthenticationProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

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
