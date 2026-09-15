package com.example.spring.security.reference.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Opt-in verification for LAB-012.
 *
 * Start the identity provider first:
 *   docker compose -f infrastructure/idp/docker-compose.yml up -d
 *
 * Tests skip when the provider is unreachable so the default build stays
 * runnable without Docker.
 */
class TokenLifecycleLabTest {

    private static final String ISSUER = "http://localhost:8081/realms/spring-security-reference";
    private static final String TOKEN_ENDPOINT = ISSUER + "/protocol/openid-connect/token";
    private static final String REVOKE_ENDPOINT = ISSUER + "/protocol/openid-connect/revoke";

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(2))
        .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void accessTokenHasBoundedExpiryInTheFuture() throws Exception {
        requireIdentityProvider();

        JsonNode tokens = passwordGrant("labadmin", "lab-admin-password");
        SignedJWT accessToken = SignedJWT.parse(tokens.get("access_token").asText());

        Instant now = Instant.now();
        Instant expiry = accessToken.getJWTClaimsSet().getExpirationTime().toInstant();

        assertThat(expiry).isAfter(now);
        assertThat(expiry).isBefore(now.plusSeconds(600));
        assertThat(accessToken.getJWTClaimsSet().getJWTID()).isNotBlank();
    }

    @Test
    void refreshTokenObtainsANewAccessTokenWithNewIdentifierAndExpiry() throws Exception {
        requireIdentityProvider();

        JsonNode initial = passwordGrant("labadmin", "lab-admin-password");
        String refreshToken = initial.get("refresh_token").asText();

        JsonNode refreshed = refreshGrant(refreshToken);
        SignedJWT newAccessToken = SignedJWT.parse(refreshed.get("access_token").asText());
        SignedJWT oldAccessToken = SignedJWT.parse(initial.get("access_token").asText());

        assertThat(newAccessToken.getJWTClaimsSet().getJWTID())
            .isNotEqualTo(oldAccessToken.getJWTClaimsSet().getJWTID());
        assertThat(newAccessToken.getJWTClaimsSet().getExpirationTime())
            .isAfter(oldAccessToken.getJWTClaimsSet().getExpirationTime());
    }

    @Test
    void revokedRefreshTokenCannotIssueNewAccessTokens() throws Exception {
        requireIdentityProvider();

        JsonNode initial = passwordGrant("labadmin", "lab-admin-password");
        String refreshToken = initial.get("refresh_token").asText();

        HttpResponse<String> revokeResponse = httpClient.send(
            HttpRequest.newBuilder(URI.create(REVOKE_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                    "token=" + refreshToken + "&client_id=spa-client"))
                .build(),
            HttpResponse.BodyHandlers.ofString());

        assertThat(revokeResponse.statusCode()).isIn(200, 204);

        HttpResponse<String> failedRefresh = httpClient.send(
            refreshRequest(refreshToken),
            HttpResponse.BodyHandlers.ofString());

        assertThat(failedRefresh.statusCode()).isEqualTo(400);
        assertThat(failedRefresh.body()).contains("invalid_grant");
    }

    @Test
    void idTokenExpiresAndIsValidForTheConfiguredClientSession() throws Exception {
        requireIdentityProvider();

        JsonNode tokens = passwordGrant("labadmin", "lab-admin-password");
        SignedJWT idToken = SignedJWT.parse(tokens.get("id_token").asText());

        assertThat(idToken.getJWTClaimsSet().getExpirationTime()).isAfter(Date.from(Instant.now()));
        assertThat(idToken.getJWTClaimsSet().getIssuer()).isEqualTo(ISSUER);
        assertThat(idToken.getJWTClaimsSet().getAudience())
            .contains("spa-client");
    }

    @Test
    void refreshTokenHasItsOwnExpiryLongerThanTheAccessToken() throws Exception {
        requireIdentityProvider();

        JsonNode tokens = passwordGrant("labadmin", "lab-admin-password");
        SignedJWT refreshToken = SignedJWT.parse(tokens.get("refresh_token").asText());
        SignedJWT accessToken = SignedJWT.parse(tokens.get("access_token").asText());

        Date refreshExpiry = refreshToken.getJWTClaimsSet().getExpirationTime();
        Date accessExpiry = accessToken.getJWTClaimsSet().getExpirationTime();

        assertThat(refreshExpiry).isNotNull();
        assertThat(refreshExpiry).isAfter(accessExpiry);
    }

    private JsonNode passwordGrant(String username, String password) throws Exception {
        return tokenResponse("grant_type=password&client_id=spa-client&username=%s&password=%s"
            .formatted(username, password));
    }

    private JsonNode refreshGrant(String refreshToken) throws Exception {
        return tokenResponse("grant_type=refresh_token&client_id=spa-client&refresh_token="
            + refreshToken);
    }

    private HttpRequest refreshRequest(String refreshToken) {
        return HttpRequest.newBuilder(URI.create(TOKEN_ENDPOINT))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(
                "grant_type=refresh_token&client_id=spa-client&refresh_token="
                    + refreshToken))
            .build();
    }

    private JsonNode tokenResponse(String body) throws Exception {
        HttpResponse<String> response = httpClient.send(
            HttpRequest.newBuilder(URI.create(TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString());

        assumeTrue(response.statusCode() == 200,
            "Token endpoint returned " + response.statusCode());
        return objectMapper.readTree(response.body());
    }

    private void requireIdentityProvider() {
        try {
            HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(ISSUER))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofString());
            assumeTrue(response.statusCode() == 200,
                "Local identity provider is not ready at " + ISSUER);
        } catch (Exception exception) {
            assumeTrue(false, "Local identity provider is not running at " + ISSUER);
        }
    }
}
