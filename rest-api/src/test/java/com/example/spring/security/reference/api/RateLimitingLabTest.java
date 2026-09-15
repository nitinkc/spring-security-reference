package com.example.spring.security.reference.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RateLimitingLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DependencyOutageSimulator dependencyOutageSimulator;

    @Test
    void burstAllowsFiveRequestsThenThrottles() throws Exception {
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(get("/rate-limit/public").header("X-Forwarded-For", "10.0.0.1"))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(get("/rate-limit/public").header("X-Forwarded-For", "10.0.0.1"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "1"));

        Thread.sleep(1_200);

        mockMvc.perform(get("/rate-limit/public").header("X-Forwarded-For", "10.0.0.1"))
                .andExpect(status().isOk());
    }

    @Test
    void differentClientHasIsolatedBucket() throws Exception {
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(get("/rate-limit/public").header("X-Forwarded-For", "10.0.0.3"))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(get("/rate-limit/public").header("X-Forwarded-For", "10.0.0.4"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/rate-limit/public").header("X-Forwarded-For", "10.0.0.3"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void failOpenReturnsFallbackWhenDown() throws Exception {
        dependencyOutageSimulator.setMode(DependencyOutageSimulator.Mode.DOWN);

        mockMvc.perform(get("/rate-limit/fail/open").header("X-Forwarded-For", "fail-open"))
                .andExpect(status().isOk())
                .andExpect(result -> result.getResponse().getContentAsString().equals("fallback"));

        dependencyOutageSimulator.setMode(DependencyOutageSimulator.Mode.HEALTHY);
    }

    @Test
    void failClosedReturns503WhenDown() throws Exception {
        dependencyOutageSimulator.setMode(DependencyOutageSimulator.Mode.DOWN);

        mockMvc.perform(get("/rate-limit/fail/closed").header("X-Forwarded-For", "fail-closed"))
                .andExpect(status().isServiceUnavailable());

        dependencyOutageSimulator.setMode(DependencyOutageSimulator.Mode.HEALTHY);
    }
}
