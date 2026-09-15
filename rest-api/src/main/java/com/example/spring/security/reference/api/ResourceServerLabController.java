package com.example.spring.security.reference.api;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Endpoints protected by the standard OAuth2 resource-server chain.
 */
@RestController
public class ResourceServerLabController {

    @GetMapping("/rs/profile")
    public Map<String, Object> profile(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
            "subject", jwt.getSubject(),
            "issuer", String.valueOf(jwt.getIssuer()),
            "keyId", String.valueOf(jwt.getHeaders().get("kid"))
        );
    }

    @GetMapping("/rs/admin/report")
    public Map<String, Object> adminReport(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("report", "admin", "subject", jwt.getSubject());
    }
}
