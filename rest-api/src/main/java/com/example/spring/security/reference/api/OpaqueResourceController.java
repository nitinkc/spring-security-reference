package com.example.spring.security.reference.api;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Protected resources under the opaque-token resource server chain.
 */
@RestController
@RequestMapping("/op")
public class OpaqueResourceController {

    @GetMapping("/resource")
    public Map<String, Object> resource(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        return Map.of("subject", principal.getName(), "scopes", principal.getAuthorities());
    }

    @GetMapping("/admin/resource")
    public Map<String, Object> adminResource(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        return Map.of("subject", principal.getName(), "admin", true);
    }
}
