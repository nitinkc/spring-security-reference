package com.example.spring.security.reference.gateway;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Gateway learning controller for LAB-016.
 *
 * In a real gateway this would proxy to downstream services using a
 * configured routing table. Here it returns the enriched request so the
 * security boundaries can be tested without a full downstream stack.
 */
@RestController
@RequestMapping("/gateway")
public class GatewayController {

    @GetMapping("/user/route")
    public Map<String, Object> userRoute(Authentication authentication,
                                        @RequestParam String target,
                                        @RequestParam(required = false) String path) {
        return buildResponse(authentication, target, path);
    }

    @GetMapping("/admin/route")
    public Map<String, Object> adminRoute(Authentication authentication,
                                         @RequestParam String target,
                                         @RequestParam(required = false) String path) {
        Map<String, Object> response = new java.util.HashMap<>(buildResponse(authentication, target, path));
        response.put("admin", true);
        return response;
    }

    private Map<String, Object> buildResponse(Authentication authentication, String target, String path) {
        Jwt jwt = (Jwt) authentication.getPrincipal();

        List<String> scopes = jwt.getClaimAsStringList("scope");
        String scopeString = scopes == null ? "" : scopes.stream().collect(Collectors.joining(" "));

        return Map.of(
            "subject", jwt.getSubject(),
            "issuer", String.valueOf(jwt.getIssuer()),
            "audience", jwt.getAudience(),
            "scope", scopeString,
            "authorities", authentication.getAuthorities(),
            "target", target,
            "path", path == null ? "/" : path,
            "forwarded", Map.of(
                "Authorization", "Bearer <token>",
                "X-User-Subject", jwt.getSubject(),
                "X-User-Scope", scopeString)
        );
    }
}
