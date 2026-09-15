package com.example.spring.security.reference.api;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TenantAwareJwtDecoder implements JwtDecoder {

    private final Map<String, NimbusJwtDecoder> decoders = new ConcurrentHashMap<>();

    public TenantAwareJwtDecoder(TenantJwkLabKeyProvider keyProvider) {
        for (String tenant : keyProvider.tenants()) {
            JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(keyProvider.jwkSet(tenant));
            JWSKeySelector<SecurityContext> jwsKeySelector =
                    new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(jwsKeySelector);

            NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
            decoder.setJwtValidator(new JwtTimestampValidator());
            decoders.put(tenant, decoder);
        }
    }

    @Override
    public Jwt decode(String token) throws BadJwtException {
        String tenant;
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            Object claim = signedJWT.getJWTClaimsSet().getClaim("tenant");
            if (claim == null) {
                throw new BadJwtException("Missing tenant claim");
            }
            tenant = claim.toString();
        } catch (ParseException exception) {
            throw new BadJwtException("Unable to parse token", exception);
        }

        NimbusJwtDecoder decoder = decoders.get(tenant);
        if (decoder == null) {
            throw new BadJwtException("Unknown tenant: " + tenant);
        }
        return decoder.decode(token);
    }
}
