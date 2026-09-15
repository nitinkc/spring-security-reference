package com.example.spring.security.reference.api;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Set;

@Configuration
@EnableWebSecurity
public class DelegatedAccessSecurityConfig {

    public static final Set<String> TRUSTED_ACTORS = Set.of("trusted-support-service");

    @Bean
    public JwtDecoder delegationJwtDecoder(DelegationJwkLabKeyProvider keyProvider) {
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(keyProvider.jwkSet());
        JWSKeySelector<SecurityContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(jwsKeySelector);

        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(delegationJwtValidator());
        return decoder;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 500)
    public SecurityFilterChain delegatedAccessFilterChain(HttpSecurity http, JwtDecoder delegationJwtDecoder)
            throws Exception {
        return http
                .securityMatcher("/delegated/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt
                                .decoder(delegationJwtDecoder)
                                .jwtAuthenticationConverter(delegationJwtAuthenticationConverter())))
                .build();
    }

    private OAuth2TokenValidator<Jwt> delegationJwtValidator() {
        return new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                new ActorAllowListValidator(TRUSTED_ACTORS));
    }

    private JwtAuthenticationConverter delegationJwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("roles");
        authoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
