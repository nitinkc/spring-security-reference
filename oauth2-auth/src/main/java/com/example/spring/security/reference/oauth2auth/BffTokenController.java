package com.example.spring.security.reference.oauth2auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * BFF endpoints for LAB-020.
 *
 * The token lives in the HTTP session; the browser only sees a session cookie.
 */
@RestController
public class BffTokenController {

    private final OAuth2AuthorizedClientRepository clientRepository;

    public BffTokenController(OAuth2AuthorizedClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @GetMapping("/bff/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("bff-ready");
    }

    @GetMapping("/bff/downstream")
    public ResponseEntity<Map<String, String>> downstream(Authentication authentication, HttpServletRequest request) {
        OAuth2AuthorizedClient client = clientRepository.loadAuthorizedClient(
                OAuth2AuthConfig.CLIENT_REGISTRATION_ID, authentication, request);

        if (client == null) {
            return ResponseEntity.status(401).body(Map.of("error", "no_authorized_client"));
        }

        String token = client.getAccessToken().getTokenValue();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        return ResponseEntity.ok(Map.of(
                "downstream_authorization", headers.getFirst(HttpHeaders.AUTHORIZATION),
                "tokenStored", "server-side"));
    }
}
