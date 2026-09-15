package com.example.spring.security.reference.gateway;

import com.example.spring.security.reference.commonsecurity.JwkLabKeyProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * Minimal API gateway for LAB-016.
 *
 * The gateway validates incoming bearer tokens, enforces scopes, and forwards
 * requests to a downstream target. In this lab the target is parameterized, but
 * a real deployment uses a service-discovery registry.
 */
@EnableWebSecurity
@Configuration
public class GatewayConfig {

    public static final String ISSUER = "https://issuer.example.test";
    public static final String AUDIENCE = "spring-security-reference-api";

    @Bean
    public JwtDecoder gatewayJwtDecoder(JwkLabKeyProvider keyProvider) {
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(keyProvider.jwkSet());
        JWSKeySelector<SecurityContext> jwsKeySelector =
            new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(jwsKeySelector);

        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(gatewayJwtValidator());
        return decoder;
    }

    @Bean
    public SecurityFilterChain gatewayFilterChain(HttpSecurity http, JwtDecoder gatewayJwtDecoder) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/gateway/admin/**").hasAuthority("SCOPE_ADMIN")
                .requestMatchers("/gateway/user/**").hasAuthority("SCOPE_USER")
                .anyRequest().authenticated())
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(jwt -> jwt
                    .decoder(gatewayJwtDecoder)
                    .jwtAuthenticationConverter(gatewayJwtAuthenticationConverter())))
            .build();
    }

    private OAuth2TokenValidator<Jwt> gatewayJwtValidator() {
        return new DelegatingOAuth2TokenValidator<>(
            new JwtTimestampValidator(),
            new JwtIssuerValidator(ISSUER),
            new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                audience -> audience != null && audience.contains(AUDIENCE))
        );
    }

    private JwtAuthenticationConverter gatewayJwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("scope");
        authoritiesConverter.setAuthorityPrefix("SCOPE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
