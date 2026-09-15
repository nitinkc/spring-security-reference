package com.example.spring.security.reference.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ResilienceLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DependencyOutageSimulator outageSimulator;

    @Autowired
    private ResilientOpaqueTokenIntrospector introspector;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void resetState() {
        outageSimulator.setMode(DependencyOutageSimulator.Mode.HEALTHY);
        introspector.clearCache();
    }

    @AfterEach
    void restoreHealthy() {
        outageSimulator.setMode(DependencyOutageSimulator.Mode.HEALTHY);
    }

    @Test
    void healthyDependencyAllowsAccess() throws Exception {
        String token = issueToken("alice");

        mockMvc.perform(get("/resilient/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void missingTokenIsRejected() throws Exception {
        mockMvc.perform(get("/resilient/data"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownTokenIsRejectedWhenHealthy() throws Exception {
        mockMvc.perform(get("/resilient/data").header("Authorization", "Bearer not-a-real-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void outageFailsClosedForUncachedToken() throws Exception {
        String token = issueToken("bob");
        outageSimulator.setMode(DependencyOutageSimulator.Mode.DOWN);

        mockMvc.perform(get("/resilient/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void outageAllowsContinuityForRecentlyVerifiedToken() throws Exception {
        String token = issueToken("carol");

        mockMvc.perform(get("/resilient/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        outageSimulator.setMode(DependencyOutageSimulator.Mode.DOWN);

        mockMvc.perform(get("/resilient/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void slowDependencyTimesOutAndFailsClosed() throws Exception {
        String token = issueToken("dave");
        outageSimulator.setMode(DependencyOutageSimulator.Mode.SLOW);

        mockMvc.perform(get("/resilient/data").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    private String issueToken(String subject) throws Exception {
        String response = mockMvc.perform(post("/resilient/issue").param("subject", subject))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return (String) objectMapper.readValue(response, java.util.Map.class).get("access_token");
    }
}
