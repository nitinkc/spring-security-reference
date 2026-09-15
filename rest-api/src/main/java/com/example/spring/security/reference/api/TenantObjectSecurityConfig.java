package com.example.spring.security.reference.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class TenantObjectSecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 700)
    public SecurityFilterChain tenantObjectFilterChain(HttpSecurity http,
                                                       TenantAwareJwtDecoder tenantAwareJwtDecoder) throws Exception {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt ->
                ((List<String>) jwt.getClaim("roles")).stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                        .collect(Collectors.toList()));

        return http
                .securityMatcher("/tenant-obj/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(tenantAwareJwtDecoder).jwtAuthenticationConverter(converter)))
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .build();
    }
}
