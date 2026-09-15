package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.BrowserSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(BrowserLabController.class)
@Import(BrowserSecurityConfig.class)
@ContextConfiguration(classes = {BrowserLabController.class, BrowserSecurityConfig.class})
class BrowserSessionLabTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publicBrowserPageAllowsAnonymousAccess() throws Exception {
        mockMvc.perform(get("/browser/public"))
            .andExpect(status().isOk());
    }

    @Test
    void protectedBrowserPageRedirectsAnonymousUsersToLogin() throws Exception {
        mockMvc.perform(get("/browser/profile"))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    void validFormLoginEstablishesAnAuthenticatedSession() throws Exception {
        mockMvc.perform(formLogin().user("browseruser").password("password"))
            .andExpect(status().is3xxRedirection())
            .andExpect(authenticated().withUsername("browseruser"));
    }

    @Test
    void invalidFormLoginDoesNotAuthenticate() throws Exception {
        mockMvc.perform(formLogin().user("browseruser").password("wrong"))
            .andExpect(unauthenticated());
    }

    @Test
    void sessionIdentifierChangesAfterLoginToPreventFixation() throws Exception {
        MockHttpSession preAuthenticationSession = new MockHttpSession();
        String preAuthenticationId = preAuthenticationSession.getId();

        mockMvc.perform(get("/browser/profile").session(preAuthenticationSession))
            .andExpect(status().is3xxRedirection());

        MvcResult result = mockMvc.perform(post("/login")
                .session(preAuthenticationSession)
                .with(csrf())
                .param("username", "browseruser")
                .param("password", "password"))
            .andExpect(authenticated())
            .andReturn();

        String postAuthenticationId = result.getRequest().getSession(false).getId();
        assertThat(postAuthenticationId).isNotEqualTo(preAuthenticationId);
    }

    @Test
    void logoutInvalidatesTheAuthenticatedSession() throws Exception {
        MockHttpSession session = (MockHttpSession) mockMvc.perform(
                formLogin().user("browseruser").password("password"))
            .andExpect(authenticated())
            .andReturn()
            .getRequest()
            .getSession(false);

        mockMvc.perform(post("/logout").session(session).with(csrf()))
            .andExpect(unauthenticated());

        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void browserRoleRulesStillApply() throws Exception {
        mockMvc.perform(get("/browser/admin/report").with(user("browseruser").roles("USER")))
            .andExpect(status().isForbidden());

        mockMvc.perform(get("/browser/admin/report").with(user("browseradmin").roles("ADMIN")))
            .andExpect(status().isOk());
    }
}
