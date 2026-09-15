package com.example.spring.security.reference.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
@EnableWebSecurity
public class ApiKeyAuthConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 200)
    public SecurityFilterChain apiKeyFilterChain(HttpSecurity http, ApiKeyAuthenticationFilter apiKeyAuthenticationFilter)
            throws Exception {
        http
                .securityMatcher("/apikey/**")
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(apiKeyAuthenticationFilter, AuthorizationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/apikey/user").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                        .requestMatchers("/apikey/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated());
        return http.build();
    }
}
