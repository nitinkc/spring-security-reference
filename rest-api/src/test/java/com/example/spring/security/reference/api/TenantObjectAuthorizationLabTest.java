package com.example.spring.security.reference.api;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TenantObjectAuthorizationLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantJwkLabKeyProvider keyProvider;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void ownerCanReadOwnDocument() throws Exception {
        String aliceToken = createToken("alice", "tenant-a", List.of("USER"));
        long documentId = createDocument(aliceToken, "alice's secret");

        mockMvc.perform(get("/tenant-obj/documents/" + documentId)
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk());
    }

    @Test
    void sameTenantNonOwnerIsDenied() throws Exception {
        String aliceToken = createToken("alice", "tenant-a", List.of("USER"));
        String bobToken = createToken("bob", "tenant-a", List.of("USER"));
        long documentId = createDocument(aliceToken, "alice's secret");

        mockMvc.perform(get("/tenant-obj/documents/" + documentId)
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void otherTenantUserIsDenied() throws Exception {
        String aliceToken = createToken("alice", "tenant-a", List.of("USER"));
        String carolToken = createToken("carol", "tenant-b", List.of("USER"));
        long documentId = createDocument(aliceToken, "alice's secret");

        mockMvc.perform(get("/tenant-obj/documents/" + documentId)
                        .header("Authorization", "Bearer " + carolToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void sameTenantAdminCanRead() throws Exception {
        String aliceToken = createToken("alice", "tenant-a", List.of("USER"));
        String adminToken = createToken("admin", "tenant-a", List.of("ADMIN"));
        long documentId = createDocument(aliceToken, "alice's secret");

        mockMvc.perform(get("/tenant-obj/documents/" + documentId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }

    @Test
    void missingTokenIsRejected() throws Exception {
        mockMvc.perform(get("/tenant-obj/documents/1"))
                .andExpect(status().isUnauthorized());
    }

    private long createDocument(String token, String content) throws Exception {
        MvcResult result = mockMvc.perform(post("/tenant-obj/documents")
                        .param("content", content)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        String json = result.getResponse().getContentAsString();
        Map<String, Object> body = objectMapper.readValue(json, Map.class);
        Number id = (Number) body.get("id");
        return id.longValue();
    }

    private String createToken(String subject, String tenant, List<String> roles) throws Exception {
        RSAKey rsaKey = keyProvider.rsaKey(tenant);
        RSASSASigner signer = new RSASSASigner(rsaKey.toRSAPrivateKey());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("roles", roles)
                .claim("tenant", tenant)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
