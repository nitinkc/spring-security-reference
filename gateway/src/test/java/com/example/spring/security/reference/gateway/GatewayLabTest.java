package com.example.spring.security.reference.gateway;

import com.example.spring.security.reference.commonsecurity.JwkLabKeyProvider;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
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

@WebMvcTest(GatewayController.class)
@Import(GatewayConfig.class)
@ContextConfiguration(classes = {GatewayController.class, GatewayConfig.class, JwkLabKeyProvider.class})
class GatewayLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwkLabKeyProvider keyProvider;

    @Test
    void authenticatedUserCanReachUserRoute() throws Exception {
        String token = tokenWithScope("USER");

        mockMvc.perform(get("/gateway/user/route")
                .param("target", "user-service")
                .header("Authorization", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.subject").value("gateway-user"));
    }

    @Test
    void authenticatedUserCannotReachAdminRoute() throws Exception {
        String token = tokenWithScope("USER");

        mockMvc.perform(get("/gateway/admin/route")
                .param("target", "admin-service")
                .header("Authorization", token))
            .andExpect(status().isForbidden());
    }

    @Test
    void adminScopeCanReachAdminRoute() throws Exception {
        String token = tokenWithScope("ADMIN");

        mockMvc.perform(get("/gateway/admin/route")
                .param("target", "admin-service")
                .header("Authorization", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.admin").value(true));
    }

    @Test
    void missingTokenIsRejected() throws Exception {
        mockMvc.perform(get("/gateway/user/route").param("target", "user-service"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void gatewayForwardsEnrichedHeadersInResponse() throws Exception {
        String token = tokenWithScope("USER");

        mockMvc.perform(get("/gateway/user/route")
                .param("target", "user-service")
                .param("path", "/api/resource")
                .header("Authorization", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.forwarded['X-User-Subject']").value("gateway-user"))
            .andExpect(jsonPath("$.forwarded['X-User-Scope']").value("USER"));
    }

    private String tokenWithScope(String scope) throws Exception {
        Instant now = Instant.now();
        RSAKey key = keyProvider.currentKey();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("gateway-user")
            .issuer(GatewayConfig.ISSUER)
            .audience(GatewayConfig.AUDIENCE)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
            .claim("scope", List.of(scope))
            .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(key.getKeyID())
            .type(JOSEObjectType.JWT)
            .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(key));
        return "Bearer " + signedJwt.serialize();
    }
}
