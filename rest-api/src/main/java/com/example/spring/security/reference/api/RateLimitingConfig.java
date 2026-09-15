package com.example.spring.security.reference.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
@EnableWebSecurity
public class RateLimitingConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 800)
    public SecurityFilterChain rateLimitingFilterChain(HttpSecurity http,
                                                       RateLimitingFilter rateLimitingFilter) throws Exception {
        return http
                .securityMatcher("/rate-limit/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(rateLimitingFilter, AuthorizationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/rate-limit/public").permitAll()
                        .requestMatchers("/rate-limit/fail/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, authException) ->
                                response.setStatus(HttpStatus.UNAUTHORIZED.value())))
                .build();
    }
}
