package com.example.spring.security.reference.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
@EnableWebSecurity
public class MtlsAuthConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 100)
    public SecurityFilterChain mTlsSecurityFilterChain(HttpSecurity http) throws Exception {
        UserDetails user = User.builder()
                .username("mtls-user")
                .password("{noop}unused")
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("mtls-admin")
                .password("{noop}unused")
                .roles("ADMIN")
                .build();
        UserDetailsService userDetailsService = new InMemoryUserDetailsManager(List.of(user, admin));

        http
                .securityMatcher("/mtls/**")
                .csrf(AbstractHttpConfigurer::disable)
                .x509(x509 -> x509
                        .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                        .userDetailsService(userDetailsService))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/mtls/user").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                        .requestMatchers("/mtls/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated());
        return http.build();
    }
}
