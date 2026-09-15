package com.example.spring.security.reference.oauth2auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * BFF token handling for LAB-020.
 *
 * The browser holds a session cookie; the access token is stored server-side in
 * the HTTP session. This is the standard Backend-for-Frontend pattern that keeps
 * tokens out of the browser and the associated XSS/CSX leak surface.
 */
@Configuration
public class BffTokenConfig {

    @Bean
    public OAuth2AuthorizedClientRepository bffAuthorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }
}
