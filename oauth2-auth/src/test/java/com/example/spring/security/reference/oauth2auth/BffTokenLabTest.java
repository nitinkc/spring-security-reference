package com.example.spring.security.reference.oauth2auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class BffTokenLabTest {

    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void authorizedClientRepositoryIsHttpSessionBacked() {
        assertThat(authorizedClientRepository)
                .isInstanceOf(HttpSessionOAuth2AuthorizedClientRepository.class);
    }

    @Test
    void healthEndpointIsReachableWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/bff/health"))
                .andExpect(status().isOk())
                .andExpect(content().string("bff-ready"));
    }

    @Test
    void downstreamEndpointRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/bff/downstream"))
                .andExpect(status().is3xxRedirection());
    }
}
