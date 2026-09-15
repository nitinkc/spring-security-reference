package com.example.spring.security.reference.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ApiKeysAndQuotasLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApiKeyRateLimiter rateLimiter;

    @BeforeEach
    void resetRateLimiter() {
        rateLimiter.reset();
    }

    @Test
    void userKeyIsAccepted() throws Exception {
        mockMvc.perform(get("/apikey/user").header("X-API-Key", "api-key-user"))
                .andExpect(status().isOk())
                .andExpect(content().string("API key user: user-key"));
    }

    @Test
    void adminKeyIsAccepted() throws Exception {
        mockMvc.perform(get("/apikey/admin").header("X-API-Key", "api-key-admin"))
                .andExpect(status().isOk())
                .andExpect(content().string("API key admin: admin-key [ROLE_ADMIN]"));
    }

    @Test
    void userKeyCannotAccessAdminRoute() throws Exception {
        mockMvc.perform(get("/apikey/admin").header("X-API-Key", "api-key-user"))
                .andExpect(status().isForbidden());
    }

    @Test
    void missingKeyIsRejected() throws Exception {
        mockMvc.perform(get("/apikey/user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidKeyIsRejected() throws Exception {
        mockMvc.perform(get("/apikey/user").header("X-API-Key", "invalid-key"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void quotaIsEnforced() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(get("/apikey/user").header("X-API-Key", "api-key-user"))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/apikey/user").header("X-API-Key", "api-key-user"))
                .andExpect(status().isTooManyRequests());
    }
}
