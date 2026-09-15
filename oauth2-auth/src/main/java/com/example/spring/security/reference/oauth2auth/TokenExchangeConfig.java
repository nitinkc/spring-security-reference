package com.example.spring.security.reference.oauth2auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;

/**
 * Token-exchange configuration for LAB-019.
 *
 * The delegated client uses RFC 8693 token exchange to trade a subject token
 * (typically an access token from the SPA login) for a token scoped to a
 * downstream service. The token URI and audience point to the local Keycloak
 * realm. A real deployment would add an explicit audience parameter through a
 * custom {@code TokenExchangeGrantRequestEntityConverter}.
 */
@Configuration
public class TokenExchangeConfig {

    public static final String TOKEN_EXCHANGE_CLIENT_REGISTRATION_ID = OAuth2AuthConfig.TOKEN_EXCHANGE_CLIENT_REGISTRATION_ID;
    public static final String DELEGATION_REST_CLIENT_BEAN = "delegationRestClient";

    @Bean
    public OAuth2AuthorizedClientManager tokenExchangeAuthorizedClientManager(
            ClientRegistrationRepository clientRegistrations,
            OAuth2AuthorizedClientService authorizedClientService) {

        TokenExchangeOAuth2AuthorizedClientProvider provider =
                new TokenExchangeOAuth2AuthorizedClientProvider();
        provider.setAccessTokenResponseClient(new RestClientTokenExchangeTokenResponseClient());

        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrations, authorizedClientService);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean(DELEGATION_REST_CLIENT_BEAN)
    public RestClient delegationRestClient(OAuth2AuthorizedClientManager tokenExchangeAuthorizedClientManager) {
        OAuth2ClientHttpRequestInterceptor interceptor =
                new OAuth2ClientHttpRequestInterceptor(tokenExchangeAuthorizedClientManager);

        return RestClient.builder()
                .requestInterceptor(interceptor)
                .build();
    }
}
