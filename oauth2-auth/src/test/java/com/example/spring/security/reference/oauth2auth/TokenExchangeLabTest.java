package com.example.spring.security.reference.oauth2auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
class TokenExchangeLabTest {

    @Autowired
    private ClientRegistrationRepository registrations;

    @Autowired
    @Qualifier("tokenExchangeAuthorizedClientManager")
    private OAuth2AuthorizedClientManager tokenExchangeManager;

    @Autowired
    @Qualifier(TokenExchangeConfig.DELEGATION_REST_CLIENT_BEAN)
    private RestClient delegationRestClient;

    @Test
    void tokenExchangeClientIsRegistered() {
        ClientRegistration registration = registrations.findByRegistrationId(
                TokenExchangeConfig.TOKEN_EXCHANGE_CLIENT_REGISTRATION_ID);

        assertThat(registration).isNotNull();
        assertThat(registration.getClientName()).isEqualTo("Spring Security Reference Delegation Client");
        assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
        assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(
                OAuth2AuthConfig.ISSUER + "/protocol/openid-connect/token");
        assertThat(registration.getScopes()).contains("spring-security-reference-api");
        assertThat(registration.getClientAuthenticationMethod().getValue()).isEqualTo("client_secret_basic");
    }

    @Test
    void tokenExchangeManagerIsPresent() {
        assertThat(tokenExchangeManager).isNotNull();
    }

    @Test
    void delegationRestClientIsConfigured() {
        assertThat(delegationRestClient).isNotNull();
    }
}
