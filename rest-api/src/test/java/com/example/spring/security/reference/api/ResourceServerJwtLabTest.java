package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.JwkLabKeyProvider;
import com.example.spring.security.reference.commonsecurity.ResourceServerSecurityConfig;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ResourceServerLabController.class)
@Import({ResourceServerSecurityConfig.class, JwkLabKeyProvider.class})
@ContextConfiguration(classes = {ResourceServerLabController.class,
    ResourceServerSecurityConfig.class, JwkLabKeyProvider.class})
class ResourceServerJwtLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwkLabKeyProvider keyProvider;

    @Test
    void validTokenIsAccepted() throws Exception {
        mockMvc.perform(get("/rs/profile").header("Authorization", bearer(validClaims().build())))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.subject").value("alice"))
            .andExpect(jsonPath("$.keyId").value(JwkLabKeyProvider.CURRENT_KEY_ID));
    }

    @Test
    void missingTokenIsRejected() throws Exception {
        mockMvc.perform(get("/rs/profile"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void malformedTokenIsRejected() throws Exception {
        mockMvc.perform(get("/rs/profile").header("Authorization", "Bearer not-a-jwt"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        JWTClaimsSet claims = validClaims()
            .issueTime(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)))
            .expirationTime(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
            .build();

        mockMvc.perform(get("/rs/profile").header("Authorization", bearer(claims)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        JWTClaimsSet claims = validClaims().issuer("https://attacker.example.test").build();

        mockMvc.perform(get("/rs/profile").header("Authorization", bearer(claims)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        JWTClaimsSet claims = validClaims().audience("another-api").build();

        mockMvc.perform(get("/rs/profile").header("Authorization", bearer(claims)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenSignedByAnUntrustedKeyIsRejected() throws Exception {
        RSAKey attackerKey = new RSAKeyGenerator(2048).keyID(JwkLabKeyProvider.CURRENT_KEY_ID).generate();

        mockMvc.perform(get("/rs/profile")
                .header("Authorization", bearer(validClaims().build(), attackerKey)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownKeyIdIsRejected() throws Exception {
        RSAKey unknownKey = new RSAKeyGenerator(2048).keyID("unknown-key").generate();

        mockMvc.perform(get("/rs/profile")
                .header("Authorization", bearer(validClaims().build(), unknownKey)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenSignedByThePreviousKeyIsAcceptedDuringOverlap() throws Exception {
        JWTClaimsSet claims = validClaims().build();
        String token = bearer(claims, keyProvider.previousKey());

        mockMvc.perform(get("/rs/profile").header("Authorization", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keyId").value(JwkLabKeyProvider.PREVIOUS_KEY_ID));
    }

    @Test
    void insufficientAuthorityIsForbidden() throws Exception {
        JWTClaimsSet claims = validClaims().claim("roles", List.of("USER")).build();

        mockMvc.perform(get("/rs/admin/report").header("Authorization", bearer(claims)))
            .andExpect(status().isForbidden());
    }

    @Test
    void adminRoleClaimGrantsAdminAccess() throws Exception {
        JWTClaimsSet claims = validClaims().claim("roles", List.of("ADMIN")).build();

        mockMvc.perform(get("/rs/admin/report").header("Authorization", bearer(claims)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.report").value("admin"));
    }

    private JWTClaimsSet.Builder validClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
            .subject("alice")
            .issuer(ResourceServerSecurityConfig.ISSUER)
            .audience(ResourceServerSecurityConfig.AUDIENCE)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
            .claim("roles", List.of("USER"));
    }

    private String bearer(JWTClaimsSet claims) throws Exception {
        return bearer(claims, keyProvider.currentKey());
    }

    private String bearer(JWTClaimsSet claims, RSAKey signingKey) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(signingKey.getKeyID())
            .type(JOSEObjectType.JWT)
            .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(signingKey));
        return "Bearer " + signedJwt.serialize();
    }
}
