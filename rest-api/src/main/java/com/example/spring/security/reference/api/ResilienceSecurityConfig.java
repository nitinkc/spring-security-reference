package com.example.spring.security.reference.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class ResilienceSecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 400)
    public SecurityFilterChain resilienceFilterChain(HttpSecurity http,
                                                       ResilientOpaqueTokenIntrospector introspector) throws Exception {
        return http
                .securityMatcher("/resilient/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/resilient/issue", "/resilient/mode").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .opaqueToken(opaque -> opaque.introspector(introspector)))
                .build();
    }
}
