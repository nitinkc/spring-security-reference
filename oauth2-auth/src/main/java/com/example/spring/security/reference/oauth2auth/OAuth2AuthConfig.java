package com.example.spring.security.reference.oauth2auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * OAuth2 / OIDC login client for LAB-011.
 *
 * The client is configured against the local Keycloak realm exported in
 * infrastructure/idp. It uses the Authorization Code grant with PKCE, exact
 * redirect URIs, and explicit scopes. In a real deployment the secret would be
 * supplied via Spring Cloud Config, Vault, or environment secrets and never
 * appear in source control.
 */
@EnableWebSecurity
@Configuration
public class OAuth2AuthConfig {

    public static final String CLIENT_REGISTRATION_ID = "spring-security-reference";
    public static final String API_CLIENT_REGISTRATION_ID = ClientCredentialsConfig.API_CLIENT_REGISTRATION_ID;
    public static final String TOKEN_EXCHANGE_CLIENT_REGISTRATION_ID = "token-exchange-client";
    public static final String ISSUER = "http://localhost:8081/realms/spring-security-reference";
    public static final String EXPECTED_AUDIENCE = "spring-security-reference-api";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration.ClientSettings spaSettings = ClientRegistration.ClientSettings.builder()
            .requireProofKey(true)
            .build();

        ClientRegistration spaClient = ClientRegistration
            .withRegistrationId(CLIENT_REGISTRATION_ID)
            .clientName("Spring Security Reference SPA")
            .clientId("spa-client")
            // Public client — no client secret.
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/login/oauth2/code/spring-security-reference")
            .scope("openid", "profile", "email", "roles")
            .authorizationUri(ISSUER + "/protocol/openid-connect/auth")
            .tokenUri(ISSUER + "/protocol/openid-connect/token")
            .userInfoUri(ISSUER + "/protocol/openid-connect/userinfo")
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .jwkSetUri(ISSUER + "/protocol/openid-connect/certs")
            .clientSettings(spaSettings)
            .build();

        ClientRegistration apiClient = ClientRegistration
            .withRegistrationId(API_CLIENT_REGISTRATION_ID)
            .clientName("Spring Security Reference API Client")
            .clientId("api-client")
            .clientSecret("lab-api-client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("spring-security-reference-api")
            .tokenUri(ISSUER + "/protocol/openid-connect/token")
            .build();

        ClientRegistration tokenExchangeClient = ClientRegistration
            .withRegistrationId(TOKEN_EXCHANGE_CLIENT_REGISTRATION_ID)
            .clientName("Spring Security Reference Delegation Client")
            .clientId("api-client")
            .clientSecret("lab-api-client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
            .scope("spring-security-reference-api")
            .tokenUri(ISSUER + "/protocol/openid-connect/token")
            .build();

        return new InMemoryClientRegistrationRepository(spaClient, apiClient, tokenExchangeClient);
    }

    @Bean
    public SecurityFilterChain oAuth2LoginFilterChain(HttpSecurity http,
                                                      ClientRegistrationRepository clientRegistrationRepository,
                                                      AuthenticationSuccessHandler successHandler,
                                                      OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService,
                                                      OAuth2AuthorizedClientRepository authorizedClientRepository) throws Exception {

        DefaultOAuth2AuthorizationRequestResolver resolver =
            new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/oauth2/**", "/login/**", "/bff/health", "/error").permitAll()
                .anyRequest().authenticated())
            .oauth2Login(oauth2 -> oauth2
                .clientRegistrationRepository(clientRegistrationRepository)
                .authorizedClientRepository(authorizedClientRepository)
                .authorizationEndpoint(endpoint -> endpoint
                    .authorizationRequestResolver(resolver))
                .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService))
                .successHandler(successHandler))
            .build();
    }

    @Bean
    public AuthenticationSuccessHandler oAuth2SuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler();
    }
}
