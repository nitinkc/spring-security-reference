package com.example.spring.security.reference.commonsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Browser-facing security chain for LAB-006, LAB-007, and LAB-008.
 *
 * This chain is deliberately separate from the stateless REST chain so cookie
 * sessions, CSRF protection, CORS, and security headers can be demonstrated
 * without weakening bearer-token endpoints.
 */
@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class BrowserSecurityConfig {

    static final String ALLOWED_ORIGIN = "https://app.example.test";

    @Bean
    public SecurityFilterChain browserFilterChain(HttpSecurity http) throws Exception {
        return http
            .securityMatcher("/browser/**", "/login", "/logout")
            .authenticationManager(new ProviderManager(browserAuthenticationProvider()))
            .cors(cors -> cors.configurationSource(browserCorsConfigurationSource()))
            .headers(headers -> headers
                .frameOptions(frame -> frame.deny())
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; frame-ancestors 'none'"))
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation(fixation -> fixation.changeSessionId())
                .sessionAuthenticationStrategy(new SessionFixationProtectionStrategy()))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/browser/public").permitAll()
                .requestMatchers("/browser/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .formLogin(form -> form.permitAll())
            .logout(logout -> logout
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID"))
            .build();
    }

    private DaoAuthenticationProvider browserAuthenticationProvider() {
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager(
            User.withUsername("browseruser")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build(),
            User.withUsername("browseradmin")
                .password(passwordEncoder.encode("password"))
                .roles("ADMIN")
                .build()
        );

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsManager);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    private UrlBasedCorsConfigurationSource browserCorsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(ALLOWED_ORIGIN));
        configuration.setAllowedMethods(List.of("GET", "POST"));
        configuration.setAllowedHeaders(List.of("Content-Type", "X-CSRF-TOKEN"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/browser/**", configuration);
        return source;
    }
}
