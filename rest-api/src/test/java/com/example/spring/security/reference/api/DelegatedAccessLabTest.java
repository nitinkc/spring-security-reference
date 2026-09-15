package com.example.spring.security.reference.api;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class DelegatedAccessLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DelegationJwkLabKeyProvider keyProvider;

    @Test
    void directTokenWithoutActorIsAccepted() throws Exception {
        String token = createToken("alice", null, Instant.now(), Instant.now().plusSeconds(300));

        mockMvc.perform(get("/delegated/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("data for alice"));
    }

    @Test
    void trustedActorOnBehalfOfUserIsAccepted() throws Exception {
        String token = createToken("alice", "trusted-support-service", Instant.now(), Instant.now().plusSeconds(300));

        mockMvc.perform(get("/delegated/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("data for alice via trusted-support-service"));
    }

    @Test
    void untrustedActorIsRejected() throws Exception {
        String token = createToken("alice", "malicious-service", Instant.now(), Instant.now().plusSeconds(300));

        mockMvc.perform(get("/delegated/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = createToken("alice", null, Instant.now().minusSeconds(400), Instant.now().minusSeconds(100));

        mockMvc.perform(get("/delegated/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void missingTokenIsRejected() throws Exception {
        mockMvc.perform(get("/delegated/data"))
                .andExpect(status().isUnauthorized());
    }

    private String createToken(String subject, String actor, Instant issuedAt, Instant expiresAt) throws Exception {
        RSASSASigner signer = new RSASSASigner(keyProvider.rsaKey().toRSAPrivateKey());

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("roles", List.of("USER"));
        if (actor != null) {
            builder.claim("act", Map.of("sub", actor));
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyProvider.rsaKey().getKeyID()).build(),
                builder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
