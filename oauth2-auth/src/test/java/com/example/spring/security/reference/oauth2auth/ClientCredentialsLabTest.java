package com.example.spring.security.reference.oauth2auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
class ClientCredentialsLabTest {

    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    @Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private RestClient serviceClient;

    @Test
    void clientCredentialsRegistrationIsConfigured() {
        ClientRegistration registration = clientRegistrations
            .findByRegistrationId(OAuth2AuthConfig.API_CLIENT_REGISTRATION_ID);

        assertThat(registration).isNotNull();
        assertThat(registration.getClientId()).isEqualTo("api-client");
        assertThat(registration.getAuthorizationGrantType())
            .isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
        assertThat(registration.getClientAuthenticationMethod())
            .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(registration.getClientSecret()).isEqualTo("lab-api-client-secret");
        assertThat(registration.getProviderDetails().getTokenUri())
            .startsWith(OAuth2AuthConfig.ISSUER);
    }

    @Test
    void authorizedClientManagerAndServiceClientAreWired() {
        assertThat(authorizedClientManager).isNotNull();
        assertThat(authorizedClientService).isNotNull();
        assertThat(serviceClient).isNotNull();
    }
}
