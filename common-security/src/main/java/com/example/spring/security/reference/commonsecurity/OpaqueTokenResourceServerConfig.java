package com.example.spring.security.reference.commonsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Opaque-token resource server for LAB-013.
 *
 * Demonstrates how a resource server validates a bearer token by calling an
 * introspection endpoint rather than decoding a self-contained JWT.
 */
@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE + 30)
public class OpaqueTokenResourceServerConfig {

    @Bean
    public InMemoryOpaqueTokenRepository opaqueTokenRepository() {
        return new InMemoryOpaqueTokenRepository();
    }

    @Bean
    public LocalOpaqueTokenIntrospector localOpaqueTokenIntrospector(InMemoryOpaqueTokenRepository repository) {
        return new LocalOpaqueTokenIntrospector(repository);
    }

    @Bean
    public SecurityFilterChain opaqueTokenFilterChain(HttpSecurity http,
                                                      LocalOpaqueTokenIntrospector introspector) throws Exception {
        return http
            .securityMatcher("/op/**")
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/op/admin/**").hasAuthority("SCOPE_ADMIN")
                .requestMatchers("/op/issue", "/op/revoke", "/op/introspect").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(resourceServer -> resourceServer
                .opaqueToken(opaque -> opaque.introspector(introspector)))
            .build();
    }
}
