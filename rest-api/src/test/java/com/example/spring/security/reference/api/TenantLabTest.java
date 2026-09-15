package com.example.spring.security.reference.api;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TenantLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantJwkLabKeyProvider keyProvider;

    @Test
    void validTenantATokenIsAccepted() throws Exception {
        String token = createToken("tenant-a", "tenant-a", List.of("USER"), Instant.now(), Instant.now().plusSeconds(300));

        mockMvc.perform(get("/tenant/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("data for tenant-a"));
    }

    @Test
    void validTenantBTokenIsAccepted() throws Exception {
        String token = createToken("tenant-b", "tenant-b", List.of("USER"), Instant.now(), Instant.now().plusSeconds(300));

        mockMvc.perform(get("/tenant/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("data for tenant-b"));
    }

    @Test
    void noTokenIsRejected() throws Exception {
        mockMvc.perform(get("/tenant/data"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = createToken("tenant-a", "tenant-a", List.of("USER"),
                Instant.now().minusSeconds(400), Instant.now().minusSeconds(100));

        mockMvc.perform(get("/tenant/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void missingTenantClaimIsRejected() throws Exception {
        String token = createToken(null, "tenant-a", List.of("USER"), Instant.now(), Instant.now().plusSeconds(300));

        mockMvc.perform(get("/tenant/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongKeyForTenantIsRejected() throws Exception {
        String token = createToken("tenant-a", "tenant-b", List.of("USER"), Instant.now(), Instant.now().plusSeconds(300));

        mockMvc.perform(get("/tenant/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    private String createToken(String tenantClaim, String signingTenant, List<String> roles,
                               Instant issuedAt, Instant expiresAt) throws Exception {
        RSAKey rsaKey = keyProvider.rsaKey(signingTenant);
        RSASSASigner signer = new RSASSASigner(rsaKey.toRSAPrivateKey());

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject("lab-user")
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("roles", roles);
        if (tenantClaim != null) {
            builder.claim("tenant", tenantClaim);
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                builder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
