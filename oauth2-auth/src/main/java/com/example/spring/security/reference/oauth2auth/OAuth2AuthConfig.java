package com.example.spring.security.reference.oauth2auth;package com.example.commonauthoauth2;



import org.apache.logging.log4j.LogManager;import org.springframework.context.annotation.Bean;

import org.apache.logging.log4j.Logger;import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Bean;import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.context.annotation.Configuration;import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.context.annotation.Profile;import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;import org.springframework.security.oauth2.core.user.OAuth2User;

import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import org.springframework.security.oauth2.core.user.OAuth2User;/**

import org.springframework.security.web.SecurityFilterChain; * OAuth2 Authentication Configuration for Spring Security.

 * 

/** * This configuration demonstrates:

 * OAuth2 Authentication Configuration for Spring Security. * - OAuth2 login with multiple providers (Google, GitHub, etc.)

 *  * - Custom OAuth2 user service for additional user processing

 * Educational Logging: This configuration demonstrates OAuth2/OpenID Connect authentication * - Resource server configuration for API protection

 * with comprehensive logging for learning modern authentication patterns. * - Integration with existing authentication mechanisms

 *  */

 * This configuration demonstrates:@Configuration

 * - OAuth2 login with multiple providers (Google, GitHub, etc.)public class OAuth2AuthConfig {

 * - Custom OAuth2 user service for additional user processing

 * - OIDC (OpenID Connect) user info extraction    @Bean

 * - Integration with existing authentication mechanisms    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {

 */        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

@Configuration        

@Profile({"default", "oauth2-only"})        return (userRequest) -> {

@EnableWebSecurity            OAuth2User oauth2User = delegate.loadUser(userRequest);

public class OAuth2AuthConfig {            

                // Custom processing of OAuth2 user

    private static final Logger logger = LogManager.getLogger(OAuth2AuthConfig.class);            String registrationId = userRequest.getClientRegistration().getRegistrationId();

            String userNameAttributeName = userRequest.getClientRegistration()

    public OAuth2AuthConfig() {                .getProviderDetails()

        logger.info("🌐 [OAUTH2-AUTH] Initializing OAuth2 Authentication Configuration");                .getUserInfoEndpoint()

        logger.debug("📚 [LEARNING] This module provides OAuth2/OIDC authentication with external providers");                .getUserNameAttributeName();

    }            

            // You can save user to database, assign roles, etc.

    @Bean            processOAuth2User(registrationId, oauth2User);

    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {            

        logger.info("👤 [OAUTH2-AUTH] Creating custom OAuth2 User Service");            return oauth2User;

        logger.debug("📚 [LEARNING] OAuth2UserService processes user info from OAuth2 providers");        };

            }

        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

            @Bean

        return (userRequest) -> {    public OidcUserService oidcUserService() {

            logger.debug("🔄 [OAUTH2-AUTH] Processing OAuth2 user request");        OidcUserService delegate = new OidcUserService();

            logger.debug("🏷️ [OAUTH2-AUTH] Client registration: {}",         

                        userRequest.getClientRegistration().getClientName());        return (userRequest) -> {

            logger.debug("📚 [LEARNING] Loading user info from OAuth2 provider");            OidcUser oidcUser = delegate.loadUser(userRequest);

                        

            // Load the OAuth2 user from the provider            // Custom processing of OIDC user

            OAuth2User oauth2User = delegate.loadUser(userRequest);            String registrationId = userRequest.getClientRegistration().getRegistrationId();

                        processOidcUser(registrationId, oidcUser);

            logger.debug("✅ [OAUTH2-AUTH] Successfully loaded OAuth2 user: {}",             

                        oauth2User.getAttribute("name"));            return oidcUser;

            logger.debug("📧 [OAUTH2-AUTH] User email: {}",         };

                        oauth2User.getAttribute("email"));    }

            logger.debug("📊 [LEARNING] Available attributes: {}", 

                        oauth2User.getAttributes().keySet());    private void processOAuth2User(String registrationId, OAuth2User oauth2User) {

                    // Extract user information and potentially save to database

            // Here you could map OAuth2 user to your application's user model        String email = oauth2User.getAttribute("email");

            // and add custom authorities based on your business logic        String name = oauth2User.getAttribute("name");

                    String avatarUrl = null;

            return oauth2User;        

        };        switch (registrationId) {

    }            case "google":

                avatarUrl = oauth2User.getAttribute("picture");

    @Bean                break;

    public OidcUserService oidcUserService() {            case "github":

        logger.info("🆔 [OAUTH2-AUTH] Creating custom OIDC User Service");                avatarUrl = oauth2User.getAttribute("avatar_url");

        logger.debug("📚 [LEARNING] OIDC extends OAuth2 with standardized identity claims");                name = oauth2User.getAttribute("login"); // GitHub uses 'login' for username

                        break;

        OidcUserService delegate = new OidcUserService();        }

                

        return (userRequest) -> {        System.out.println("OAuth2 User authenticated:");

            logger.debug("🔄 [OAUTH2-AUTH] Processing OIDC user request");        System.out.println("  Provider: " + registrationId);

            logger.debug("🏷️ [OAUTH2-AUTH] OIDC provider: {}",         System.out.println("  Name: " + name);

                        userRequest.getClientRegistration().getClientName());        System.out.println("  Email: " + email);

                    System.out.println("  Avatar: " + avatarUrl);

            // Load the OIDC user from the provider        

            OidcUser oidcUser = delegate.loadUser(userRequest);        // Here you would typically:

                    // 1. Check if user exists in your database

            logger.debug("✅ [OAUTH2-AUTH] Successfully loaded OIDC user: {}",         // 2. Create new user record if needed

                        oidcUser.getFullName());        // 3. Assign appropriate roles based on your business logic

            logger.debug("📧 [OAUTH2-AUTH] User email: {}", oidcUser.getEmail());        // 4. Update user information if changed

            logger.debug("🔗 [OAUTH2-AUTH] Subject: {}", oidcUser.getSubject());    }

            logger.debug("📚 [LEARNING] OIDC provides standardized claims (sub, name, email, etc.)");

                private void processOidcUser(String registrationId, OidcUser oidcUser) {

            // Here you could create custom authorities based on OIDC claims        // Process OIDC-specific information (includes ID token claims)

            // or integrate with your application's user management        String subject = oidcUser.getSubject();

                    String email = oidcUser.getEmail();

            return oidcUser;        String name = oidcUser.getFullName();

        };        

    }        System.out.println("OIDC User authenticated:");

        System.out.println("  Provider: " + registrationId);

    @Bean        System.out.println("  Subject: " + subject);

    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {        System.out.println("  Name: " + name);

        logger.info("🔒 [OAUTH2-AUTH] Configuring OAuth2 Security Filter Chain");        System.out.println("  Email: " + email);

        logger.debug("📚 [LEARNING] Security filter chain defines OAuth2 authentication flow");    }

        }
        http
            .authorizeHttpRequests(authz -> {
                logger.debug("🚦 [OAUTH2-AUTH] Configuring authorization rules");
                authz.requestMatchers("/oauth2/**", "/login/**").permitAll()
                     .anyRequest().authenticated();
                logger.debug("📚 [LEARNING] OAuth2 endpoints are public, everything else requires authentication");
            })
            .oauth2Login(oauth2 -> {
                logger.debug("🔐 [OAUTH2-AUTH] Configuring OAuth2 login");
                oauth2.userInfoEndpoint(userInfo -> {
                    userInfo.userService(oauth2UserService());
                    userInfo.oidcUserService(oidcUserService());
                });
                oauth2.successHandler(new OAuth2AuthenticationSuccessHandler());
                logger.debug("📚 [LEARNING] OAuth2 login uses custom user services and success handler");
            });
        
        logger.debug("✅ [OAUTH2-AUTH] OAuth2 Security Filter Chain configured successfully");
        logger.debug("🔄 [LEARNING] Authentication flow: OAuth2 provider → user info → success handler");
        
        return http.build();
    }
}