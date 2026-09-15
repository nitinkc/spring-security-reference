package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.InMemoryOpaqueTokenRepository;
import com.example.spring.security.reference.commonsecurity.LocalOpaqueTokenIntrospector;
import com.example.spring.security.reference.commonsecurity.OpaqueTokenResourceServerConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest({OpaqueResourceController.class, OpaqueTokenController.class})
@Import({OpaqueTokenResourceServerConfig.class})
@ContextConfiguration(classes = {OpaqueResourceController.class, OpaqueTokenController.class,
    OpaqueTokenResourceServerConfig.class})
class OpaqueTokenIntrospectionLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private InMemoryOpaqueTokenRepository repository;

    @Test
    void validOpaqueTokenGrantsAccessToProtectedResource() throws Exception {
        String token = repository.issue("alice", "op-client", java.time.Instant.now().plusSeconds(300), "USER");

        mockMvc.perform(get("/op/resource")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.subject").value("alice"));
    }

    @Test
    void missingOpaqueTokenIsRejected() throws Exception {
        mockMvc.perform(get("/op/resource"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownOpaqueTokenIsRejected() throws Exception {
        mockMvc.perform(get("/op/resource")
                .header("Authorization", "Bearer does-not-exist"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredOpaqueTokenIsRejected() throws Exception {
        String token = repository.issue("alice", "op-client", java.time.Instant.now().minusSeconds(10), "USER");

        mockMvc.perform(get("/op/resource")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void insufficientScopeIsForbidden() throws Exception {
        String token = repository.issue("alice", "op-client", java.time.Instant.now().plusSeconds(300), "USER");

        mockMvc.perform(get("/op/admin/resource")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

    @Test
    void adminScopeGrantsAdminAccess() throws Exception {
        String token = repository.issue("alice", "op-client", java.time.Instant.now().plusSeconds(300), "ADMIN");

        mockMvc.perform(get("/op/admin/resource")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.admin").value(true));
    }

    @Test
    void introspectionEndpointReturnsActiveTokenDetails() throws Exception {
        String token = repository.issue("alice", "op-client", java.time.Instant.now().plusSeconds(300), "USER");

        mockMvc.perform(post("/op/introspect")
                .param("token", token)
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.sub").value("alice"))
            .andExpect(jsonPath("$.scope").value("USER"));
    }

    @Test
    void introspectionEndpointReturnsInactiveForUnknownToken() throws Exception {
        mockMvc.perform(post("/op/introspect")
                .param("token", "unknown-token")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void revokedTokenCanNoLongerAccessResources() throws Exception {
        String token = repository.issue("alice", "op-client", java.time.Instant.now().plusSeconds(300), "USER");

        mockMvc.perform(get("/op/resource")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());

        mockMvc.perform(post("/op/revoke").param("token", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.revoked").value(true));

        mockMvc.perform(get("/op/resource")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized());
    }
}
