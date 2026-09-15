package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.BrowserSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(BrowserLabController.class)
@Import(BrowserSecurityConfig.class)
@ContextConfiguration(classes = {BrowserLabController.class, BrowserSecurityConfig.class})
class BrowserCorsHeadersLabTest {

    private static final String ALLOWED_ORIGIN = "https://app.example.test";
    private static final String UNKNOWN_ORIGIN = "https://evil.example.test";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void preflightFromAllowedOriginIsApproved() throws Exception {
        mockMvc.perform(options("/browser/profile")
                .header("Origin", ALLOWED_ORIGIN)
                .header("Access-Control-Request-Method", "POST"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
            .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }

    @Test
    void preflightFromUnknownOriginIsRejected() throws Exception {
        mockMvc.perform(options("/browser/profile")
                .header("Origin", UNKNOWN_ORIGIN)
                .header("Access-Control-Request-Method", "POST"))
            .andExpect(status().isForbidden())
            .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    @Test
    void credentialedCorsResponseNeverUsesAWildcardOrigin() throws Exception {
        mockMvc.perform(get("/browser/profile")
                .header("Origin", ALLOWED_ORIGIN)
                .with(user("browseruser").roles("USER")))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN));
    }

    @Test
    void browserResponsesCarryHardenedSecurityHeaders() throws Exception {
        mockMvc.perform(get("/browser/profile").with(user("browseruser").roles("USER")))
            .andExpect(status().isOk())
            .andExpect(header().string("X-Frame-Options", "DENY"))
            .andExpect(header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(header().string("Referrer-Policy", "no-referrer"))
            .andExpect(header().string("Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'"))
            .andExpect(header().string("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate"));
    }
}
