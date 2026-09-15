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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Opt-in verification for LAB-010.
 *
 * Start the identity provider first:
 *   docker compose -f infrastructure/idp/docker-compose.yml up -d
 *
 * Each test skips itself when the provider is unreachable so the default
 * build stays runnable without Docker.
 */
class LocalIdentityProviderLabTest {

    private static final String ISSUER = "http://localhost:8081/realms/spring-security-reference";
    private static final String DISCOVERY = ISSUER + "/.well-known/openid-configuration";
    private static final String TOKEN_ENDPOINT = ISSUER + "/protocol/openid-connect/token";
    private static final String EXPECTED_AUDIENCE = "spring-security-reference-api";

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(2))
        .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void discoveryDocumentAdvertisesTheExpectedIssuerAndEndpoints() throws Exception {
        JsonNode discovery = objectMapper.readTree(requireIdentityProvider());

        assertThat(discovery.get("issuer").asText()).isEqualTo(ISSUER);
        assertThat(discovery.get("jwks_uri").asText()).startsWith(ISSUER);
        assertThat(discovery.get("authorization_endpoint").asText()).startsWith(ISSUER);
        assertThat(discovery.get("token_endpoint").asText()).isEqualTo(TOKEN_ENDPOINT);
    }

    @Test
    void providerSupportsPkceAndAuthorizationCode() throws Exception {
        JsonNode discovery = objectMapper.readTree(requireIdentityProvider());

        assertThat(readValues(discovery, "code_challenge_methods_supported")).contains("S256");
        assertThat(readValues(discovery, "grant_types_supported")).contains("authorization_code");
        assertThat(readValues(discovery, "response_types_supported")).contains("code");
    }

    @Test
    void adminUserReceivesTokenWithApiAudienceAndAdminRole() throws Exception {
        requireIdentityProvider();

        SignedJWT accessToken = SignedJWT.parse(passwordGrantAccessToken("labadmin", "lab-admin-password"));

        assertThat(accessToken.getJWTClaimsSet().getIssuer()).isEqualTo(ISSUER);
        assertThat(accessToken.getJWTClaimsSet().getAudience()).contains(EXPECTED_AUDIENCE);
        assertThat(accessToken.getJWTClaimsSet().getStringListClaim("roles")).contains("ADMIN", "USER");
        assertThat(accessToken.getHeader().getKeyID()).isNotBlank();
    }

    @Test
    void standardUserDoesNotReceiveTheAdminRole() throws Exception {
        requireIdentityProvider();

        SignedJWT accessToken = SignedJWT.parse(passwordGrantAccessToken("labuser", "lab-user-password"));

        assertThat(accessToken.getJWTClaimsSet().getStringListClaim("roles"))
            .contains("USER")
            .doesNotContain("ADMIN");
    }

    @Test
    void invalidCredentialsAreRejectedByTheProvider() throws Exception {
        requireIdentityProvider();

        HttpResponse<String> response = httpClient.send(
            tokenRequest("labadmin", "wrong-password"),
            HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).doesNotContain("access_token");
    }

    private String requireIdentityProvider() {
        try {
            HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(DISCOVERY)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            assumeTrue(response.statusCode() == 200,
                "Local identity provider is not ready at " + DISCOVERY);
            return response.body();
        } catch (Exception exception) {
            assumeTrue(false, "Local identity provider is not running at " + DISCOVERY);
            throw new IllegalStateException(exception);
        }
    }

    private String passwordGrantAccessToken(String username, String password) throws Exception {
        HttpResponse<String> response = httpClient.send(
            tokenRequest(username, password),
            HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        return objectMapper.readTree(response.body()).get("access_token").asText();
    }

    private HttpRequest tokenRequest(String username, String password) {
        String form = "grant_type=password&client_id=spa-client&username=%s&password=%s"
            .formatted(username, password);

        return HttpRequest.newBuilder(URI.create(TOKEN_ENDPOINT))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form))
            .build();
    }

    private List<String> readValues(JsonNode node, String field) {
        return objectMapper.convertValue(node.get(field), objectMapper.getTypeFactory()
            .constructCollectionType(List.class, String.class));
    }
}
