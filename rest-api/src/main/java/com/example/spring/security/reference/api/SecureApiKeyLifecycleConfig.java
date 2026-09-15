package com.example.spring.security.reference.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecureApiKeyLifecycleConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 600)
    public SecurityFilterChain secureApiKeyLifecycleFilterChain(HttpSecurity http,
                                                                 SecureApiKeyAuthenticationFilter filter) throws Exception {
        return http
                .securityMatcher("/apikey-life/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(filter, AuthorizationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/apikey-life/user").hasAuthority("SCOPE_USER")
                        .requestMatchers("/apikey-life/admin").hasAuthority("SCOPE_ADMIN")
                        .anyRequest().permitAll())
                .build();
    }
}
