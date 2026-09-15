package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.BrowserSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(BrowserLabController.class)
@Import(BrowserSecurityConfig.class)
@ContextConfiguration(classes = {BrowserLabController.class, BrowserSecurityConfig.class})
class BrowserCsrfLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void stateChangingRequestSucceedsWithAValidCsrfToken() throws Exception {
        mockMvc.perform(post("/browser/profile")
                .with(user("browseruser").roles("USER"))
                .with(csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.updated").value(true));
    }

    @Test
    void stateChangingRequestIsRejectedWithoutACsrfToken() throws Exception {
        mockMvc.perform(post("/browser/profile")
                .with(user("browseruser").roles("USER")))
            .andExpect(status().isForbidden());
    }

    @Test
    void stateChangingRequestIsRejectedWithAnInvalidCsrfToken() throws Exception {
        mockMvc.perform(post("/browser/profile")
                .with(user("browseruser").roles("USER"))
                .with(csrf().useInvalidToken()))
            .andExpect(status().isForbidden());
    }

    @Test
    void crossSiteFormSubmissionCannotChangeStateWithoutTheToken() throws Exception {
        mockMvc.perform(post("/browser/profile")
                .header("Origin", "https://evil.example.test")
                .with(user("browseruser").roles("USER")))
            .andExpect(status().isForbidden());
    }
}
