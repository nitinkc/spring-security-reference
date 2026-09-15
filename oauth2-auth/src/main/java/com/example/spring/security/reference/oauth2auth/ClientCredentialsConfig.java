package com.example.spring.security.reference.oauth2auth;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;

/**
 * Client-credentials configuration for LAB-014.
 *
 * The confidential `api-client` registered in the local Keycloak realm uses
 * machine-to-machine authentication. The client secret here is a lab value and
 * must be supplied from a secret store in any real deployment.
 */
@Configuration
public class ClientCredentialsConfig {

    public static final String API_CLIENT_REGISTRATION_ID = "api-client";

    @Bean
    public OAuth2AuthorizedClientManager clientCredentialsAuthorizedClientManager(
            ClientRegistrationRepository clientRegistrations,
            OAuth2AuthorizedClientService authorizedClientService) {

        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder
            .builder()
            .clientCredentials()
            .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrations, authorizedClientService);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean
    public RestClient serviceClient(@Qualifier("clientCredentialsAuthorizedClientManager") OAuth2AuthorizedClientManager authorizedClientManager) {
        OAuth2ClientHttpRequestInterceptor interceptor =
            new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);

        return RestClient.builder()
            .requestInterceptor(interceptor)
            .build();
    }
}
