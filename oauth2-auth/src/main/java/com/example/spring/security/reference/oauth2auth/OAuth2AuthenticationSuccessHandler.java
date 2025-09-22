package com.example.spring.security.reference.oauth2auth;package com.example.commonauthoauth2;



import org.apache.logging.log4j.LogManager;import org.springframework.security.core.Authentication;

import org.apache.logging.log4j.Logger;import org.springframework.security.oauth2.core.user.OAuth2User;

import org.springframework.security.core.Authentication;import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;import org.springframework.stereotype.Component;

import org.springframework.security.oauth2.core.user.OAuth2User;

import org.springframework.security.web.authentication.AuthenticationSuccessHandler;import jakarta.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Component;import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;

import jakarta.servlet.http.HttpServletResponse;/**

import java.io.IOException; * Custom OAuth2 Authentication Success Handler.

 * 

/** * This handler demonstrates:

 * Custom OAuth2 Authentication Success Handler. * - Custom post-authentication processing for OAuth2 users

 *  * - Redirecting users based on their OAuth2 provider

 * Educational Logging: This handler demonstrates post-authentication processing * - Extracting and processing OAuth2 user attributes

 * for OAuth2 users with comprehensive logging for learning OAuth2 flows. * - Integration with existing application user management

 *  */

 * This handler demonstrates:@Component

 * - Custom post-authentication processing for OAuth2 userspublic class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

 * - Redirecting users based on their OAuth2 provider

 * - Extracting and processing OAuth2 user attributes    @Override

 * - Integration with existing application user management    public void onAuthenticationSuccess(HttpServletRequest request, 

 */                                      HttpServletResponse response,

@Component                                      Authentication authentication) throws IOException {

public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {        

            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

    private static final Logger logger = LogManager.getLogger(OAuth2AuthenticationSuccessHandler.class);        

        // Extract user information

    public OAuth2AuthenticationSuccessHandler() {        String email = oauth2User.getAttribute("email");

        logger.info("🎯 [OAUTH2-SUCCESS] Initializing OAuth2 Authentication Success Handler");        String name = oauth2User.getAttribute("name");

        logger.debug("📚 [LEARNING] Success handler processes user after successful OAuth2 authentication");        

    }        // Determine the OAuth2 provider from the request

        String registrationId = extractRegistrationId(request);

    @Override        

    public void onAuthenticationSuccess(HttpServletRequest request,         // Perform custom business logic

                                      HttpServletResponse response,        handleUserAuthentication(registrationId, oauth2User);

                                      Authentication authentication) throws IOException {        

                // Redirect based on user type or provider

        logger.info("🎉 [OAUTH2-SUCCESS] OAuth2 authentication successful!");        String redirectUrl = determineRedirectUrl(registrationId, oauth2User);

        logger.debug("📚 [LEARNING] Processing successful OAuth2 authentication and preparing redirect");        response.sendRedirect(redirectUrl);

            }

        // Extract OAuth2 user information    

        Object principal = authentication.getPrincipal();    private String extractRegistrationId(HttpServletRequest request) {

                String requestURI = request.getRequestURI();

        if (principal instanceof OidcUser) {        if (requestURI.contains("/oauth2/code/google")) {

            handleOidcUser((OidcUser) principal, request, response);            return "google";

        } else if (principal instanceof OAuth2User) {        } else if (requestURI.contains("/oauth2/code/github")) {

            handleOAuth2User((OAuth2User) principal, request, response);            return "github";

        } else {        }

            logger.warn("⚠️ [OAUTH2-SUCCESS] Unknown principal type: {}",         return "unknown";

                       principal.getClass().getSimpleName());    }

            response.sendRedirect("/");    

        }    private void handleUserAuthentication(String registrationId, OAuth2User oauth2User) {

    }        String email = oauth2User.getAttribute("email");

            String name = oauth2User.getAttribute("name");

    private void handleOidcUser(OidcUser oidcUser, HttpServletRequest request,         

                               HttpServletResponse response) throws IOException {        // Example business logic:

        logger.info("🆔 [OAUTH2-SUCCESS] Processing OIDC user: {}", oidcUser.getFullName());        // 1. Check if user exists in database

        logger.debug("📚 [LEARNING] OIDC user has standardized claims and ID token");        // 2. Create or update user record

                // 3. Assign roles based on email domain or other criteria

        // Log OIDC-specific information        // 4. Log authentication event

        logger.debug("👤 [OAUTH2-SUCCESS] OIDC User Details:");        

        logger.debug("   • Subject: {}", oidcUser.getSubject());        System.out.println("Processing OAuth2 authentication:");

        logger.debug("   • Full Name: {}", oidcUser.getFullName());        System.out.println("  Provider: " + registrationId);

        logger.debug("   • Email: {}", oidcUser.getEmail());        System.out.println("  User: " + name + " (" + email + ")");

        logger.debug("   • Email Verified: {}", oidcUser.getEmailVerified());        

        logger.debug("   • Issued At: {}", oidcUser.getIssuedAt());        // Example: Assign admin role to users from specific domain

        logger.debug("   • Expires At: {}", oidcUser.getExpiresAt());        if (email != null && email.endsWith("@company.com")) {

                    // Assign admin role

        // Here you could:            System.out.println("  Assigned ROLE_ADMIN based on email domain");

        // 1. Check if user exists in your database        } else {

        // 2. Create or update user profile            // Assign user role

        // 3. Assign roles based on OIDC claims            System.out.println("  Assigned ROLE_USER (default)");

        // 4. Log the authentication event        }

            }

        logger.debug("🔄 [OAUTH2-SUCCESS] User processing completed, redirecting to dashboard");    

        response.sendRedirect("/dashboard?source=oidc");    private String determineRedirectUrl(String registrationId, OAuth2User oauth2User) {

    }        // Redirect based on provider or user attributes

            String email = oauth2User.getAttribute("email");

    private void handleOAuth2User(OAuth2User oauth2User, HttpServletRequest request,         

                                 HttpServletResponse response) throws IOException {        if (email != null && email.endsWith("@company.com")) {

        String name = oauth2User.getAttribute("name");            return "/admin/dashboard"; // Admin users go to admin dashboard

        String email = oauth2User.getAttribute("email");        } else {

                    return "/user/profile";    // Regular users go to profile

        logger.info("🌐 [OAUTH2-SUCCESS] Processing OAuth2 user: {}", name);        }

        logger.debug("📚 [LEARNING] OAuth2 user has provider-specific attributes");    }

        }
        // Log OAuth2-specific information
        logger.debug("👤 [OAUTH2-SUCCESS] OAuth2 User Details:");
        logger.debug("   • Name: {}", name);
        logger.debug("   • Email: {}", email);
        logger.debug("   • Authorities: {}", oauth2User.getAuthorities());
        logger.debug("   • Available Attributes: {}", oauth2User.getAttributes().keySet());
        
        // Determine OAuth2 provider for provider-specific handling
        String registrationId = getRegistrationId(request);
        logger.debug("🏷️ [OAUTH2-SUCCESS] OAuth2 Provider: {}", registrationId);
        
        // Provider-specific processing
        switch (registrationId) {
            case "google":
                logger.debug("🔍 [OAUTH2-SUCCESS] Processing Google OAuth2 user");
                handleGoogleUser(oauth2User);
                break;
            case "github":
                logger.debug("🔍 [OAUTH2-SUCCESS] Processing GitHub OAuth2 user");
                handleGitHubUser(oauth2User);
                break;
            default:
                logger.debug("🔍 [OAUTH2-SUCCESS] Processing generic OAuth2 user");
                break;
        }
        
        // Here you could:
        // 1. Map OAuth2 attributes to your user model
        // 2. Store or update user information
        // 3. Create JWT token for API access
        // 4. Set session attributes
        
        logger.debug("🔄 [OAUTH2-SUCCESS] User processing completed, redirecting to dashboard");
        response.sendRedirect("/dashboard?source=oauth2&provider=" + registrationId);
    }
    
    private void handleGoogleUser(OAuth2User oauth2User) {
        String picture = oauth2User.getAttribute("picture");
        String locale = oauth2User.getAttribute("locale");
        
        logger.debug("🔍 [OAUTH2-SUCCESS] Google-specific attributes:");
        logger.debug("   • Profile Picture: {}", picture);
        logger.debug("   • Locale: {}", locale);
        logger.debug("📚 [LEARNING] Google provides rich profile information");
    }
    
    private void handleGitHubUser(OAuth2User oauth2User) {
        String login = oauth2User.getAttribute("login");
        String company = oauth2User.getAttribute("company");
        String location = oauth2User.getAttribute("location");
        
        logger.debug("🔍 [OAUTH2-SUCCESS] GitHub-specific attributes:");
        logger.debug("   • Login: {}", login);
        logger.debug("   • Company: {}", company);
        logger.debug("   • Location: {}", location);
        logger.debug("📚 [LEARNING] GitHub provides developer-focused profile data");
    }
    
    private String getRegistrationId(HttpServletRequest request) {
        // Extract registration ID from request URI
        String uri = request.getRequestURI();
        if (uri.contains("/oauth2/code/")) {
            String[] parts = uri.split("/oauth2/code/");
            if (parts.length > 1) {
                return parts[1];
            }
        }
        return "unknown";
    }
}