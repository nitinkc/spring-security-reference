package com.example.spring.security.reference.commonsecurity;

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
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import com.nimbusds.jose.JWSAlgorithm;
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
 * Standard OAuth2 resource-server chain for LAB-009 and LAB-015.
 *
 * This is the recommended bearer-token path. The custom JWT filter in
 * common-auth remains only as an educational example of filter mechanics.
 */
@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class ResourceServerSecurityConfig {

    public static final String ISSUER = "https://issuer.example.test";
    public static final String AUDIENCE = "spring-security-reference-api";

    @Bean
    public JwtDecoder labJwtDecoder(JwkLabKeyProvider keyProvider) {
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(keyProvider.jwkSet());
        JWSKeySelector<SecurityContext> jwsKeySelector =
            new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(jwsKeySelector);

        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(labJwtValidator());
        return decoder;
    }

    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http, JwtDecoder labJwtDecoder)
            throws Exception {
        return http
            .securityMatcher("/rs/**")
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/rs/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(jwt -> jwt
                    .decoder(labJwtDecoder)
                    .jwtAuthenticationConverter(labJwtAuthenticationConverter())))
            .build();
    }

    private OAuth2TokenValidator<Jwt> labJwtValidator() {
        return new DelegatingOAuth2TokenValidator<>(
            new JwtTimestampValidator(),
            new JwtIssuerValidator(ISSUER),
            new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                audience -> audience != null && audience.contains(AUDIENCE))
        );
    }

    private JwtAuthenticationConverter labJwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("roles");
        authoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
