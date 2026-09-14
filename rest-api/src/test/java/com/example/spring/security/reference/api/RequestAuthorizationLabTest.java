package com.example.spring.security.reference.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;

import com.example.spring.security.reference.commonauth.CustomAuthenticationProvider;
import com.example.spring.security.reference.commonauth.JwtAuthenticationFilter;
import com.example.spring.security.reference.commonsecurity.JsonAccessDeniedHandler;
import com.example.spring.security.reference.commonsecurity.JsonAuthenticationEntryPoint;
import com.example.spring.security.reference.commonsecurity.MultiAuthSecurityConfig;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.example.spring.security.reference.commonauth.JwtTokenUtil;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ApiController.class)
@Import({MultiAuthSecurityConfig.class, JwtAuthenticationFilter.class,
    JsonAuthenticationEntryPoint.class, JsonAccessDeniedHandler.class})
@ContextConfiguration(classes = {ApiController.class, MultiAuthSecurityConfig.class,
    JwtAuthenticationFilter.class, JsonAuthenticationEntryPoint.class, JsonAccessDeniedHandler.class})
class RequestAuthorizationLabTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtTokenUtil jwtTokenUtil;

    @MockitoBean
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Test
    void publicEndpointAllowsAnonymousRequests() throws Exception {
        mockMvc.perform(get("/api/public/hello"))
            .andExpect(status().isOk());
    }

    @Test
    void protectedEndpointRejectsAnonymousRequests() throws Exception {
        mockMvc.perform(get("/api/user/secure"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.error").value("authentication_required"))
            .andExpect(jsonPath("$.message").value("Authentication is required to access this resource"))
            .andExpect(jsonPath("$.path").value("/api/user/secure"))
            .andExpect(jsonPath("$.exception").doesNotExist())
            .andExpect(jsonPath("$.authorities").doesNotExist())
            .andExpect(jsonPath("$.expression").doesNotExist());
    }

    @Test
    void userCanAccessUserEndpoint() throws Exception {
        mockMvc.perform(get("/api/user/secure").with(user("learner").roles("USER")))
            .andExpect(status().isOk());
    }

    @Test
    void userCannotAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/secure").with(user("learner").roles("USER")))
            .andExpect(status().isForbidden())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.error").value("access_denied"))
            .andExpect(jsonPath("$.message").value("You do not have permission to access this resource"))
            .andExpect(jsonPath("$.path").value("/api/admin/secure"))
            .andExpect(jsonPath("$.exception").doesNotExist())
            .andExpect(jsonPath("$.authorities").doesNotExist())
            .andExpect(jsonPath("$.expression").doesNotExist());
    }

    @Test
    void adminCanAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/secure").with(user("admin").roles("ADMIN")))
            .andExpect(status().isOk());
    }
}
