package com.example.spring.security.reference.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.example.spring.security.reference.commonauth.AuthService;
import com.example.spring.security.reference.commonauth.CustomAuthenticationProvider;
import com.example.spring.security.reference.commonauth.InMemoryCredentialRepository;
import com.example.spring.security.reference.commonauth.JwtAuthenticationFilter;
import com.example.spring.security.reference.commonauth.JwtTokenUtil;
import com.example.spring.security.reference.commonauth.PasswordSecurityConfig;
import com.example.spring.security.reference.commonsecurity.JsonAccessDeniedHandler;
import com.example.spring.security.reference.commonsecurity.JsonAuthenticationEntryPoint;
import com.example.spring.security.reference.commonsecurity.MultiAuthSecurityConfig;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ApiController.class)
@Import({MultiAuthSecurityConfig.class, JwtAuthenticationFilter.class,
    CustomAuthenticationProvider.class, AuthService.class, InMemoryCredentialRepository.class,
    PasswordSecurityConfig.class, JsonAuthenticationEntryPoint.class, JsonAccessDeniedHandler.class})
@ContextConfiguration(classes = {ApiController.class, MultiAuthSecurityConfig.class,
    JwtAuthenticationFilter.class, CustomAuthenticationProvider.class, AuthService.class,
    InMemoryCredentialRepository.class, PasswordSecurityConfig.class,
    JsonAuthenticationEntryPoint.class, JsonAccessDeniedHandler.class})
class LoginAuthenticationLabTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtTokenUtil jwtTokenUtil;

    @Test
    void validCredentialsAreAuthenticatedBeforeTokenIssuance() throws Exception {
        when(jwtTokenUtil.generateToken("admin", "ROLE_ADMIN")).thenReturn("signed-token");

        mockMvc.perform(post("/api/auth/login")
                .param("username", "admin")
                .param("password", "password"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("signed-token"))
            .andExpect(jsonPath("$.username").value("admin"))
            .andExpect(jsonPath("$.role").value("ROLE_ADMIN"));

        verify(jwtTokenUtil).generateToken("admin", "ROLE_ADMIN");
    }

    @Test
    void invalidPasswordReturnsUniformUnauthorizedResponse() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .param("username", "admin")
                .param("password", "wrong"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("invalid_credentials"));

        verify(jwtTokenUtil, never()).generateToken("admin", "ROLE_ADMIN");
    }

    @Test
    void unknownUserReturnsTheSameUnauthorizedResponse() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .param("username", "unknown")
                .param("password", "password"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("invalid_credentials"));

        verify(jwtTokenUtil, never()).generateToken("unknown", "ROLE_USER");
    }
}
