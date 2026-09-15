package com.example.spring.security.reference.oauth2auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OAuth2LoginConfigurationTest {

    @Autowired
    private ClientRegistrationRepository registrations;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void registrationUsesAuthorizationCodeWithPkce() {
        ClientRegistration registration = registrations.findByRegistrationId(
            OAuth2AuthConfig.CLIENT_REGISTRATION_ID);

        assertThat(registration).isNotNull();
        assertThat(registration.getClientName()).isEqualTo("Spring Security Reference SPA");
        assertThat(registration.getClientId()).isEqualTo("spa-client");
        assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
        assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(registration.getRedirectUri()).isEqualTo(
            "http://localhost:8080/login/oauth2/code/spring-security-reference");
        assertThat(registration.getScopes()).contains("openid", "profile", "email", "roles");
        assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri()).contains("/protocol/openid-connect/userinfo");
        assertThat(registration.getProviderDetails().getJwkSetUri()).contains("/protocol/openid-connect/certs");
        assertThat(registration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint"))
            .isNull(); // defaults to issuer path if used
        assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName())
            .isEqualTo(IdTokenClaimNames.SUB);
        assertThat(registration.getClientSettings().isRequireProofKey()).isTrue();
    }

    @Test
    void registrationTargetIsTheLocalKeycloakRealm() {
        ClientRegistration registration = registrations.findByRegistrationId(
            OAuth2AuthConfig.CLIENT_REGISTRATION_ID);

        assertThat(registration.getProviderDetails().getAuthorizationUri())
            .startsWith(OAuth2AuthConfig.ISSUER);
        assertThat(registration.getProviderDetails().getTokenUri())
            .startsWith(OAuth2AuthConfig.ISSUER);
        assertThat(registration.getProviderDetails().getJwkSetUri())
            .startsWith(OAuth2AuthConfig.ISSUER);
    }

    @Test
    void protectedOAuth2PageRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/"))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    void authorizedUserCanAccessProtectedPage() throws Exception {
        mockMvc.perform(get("/").with(user("labadmin").roles("ADMIN")))
            .andExpect(status().isNotFound());
    }
}
