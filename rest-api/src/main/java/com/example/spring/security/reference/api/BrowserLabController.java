package com.example.spring.security.reference.api;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Browser-facing endpoints used by the session, CSRF, CORS, and header labs.
 */
@RestController
public class BrowserLabController {

    @GetMapping("/browser/public")
    public Map<String, Object> publicPage() {
        return Map.of("page", "public");
    }

    @GetMapping("/browser/profile")
    public Map<String, Object> profile(Authentication authentication) {
        return Map.of("user", authentication.getName());
    }

    @PostMapping("/browser/profile")
    public Map<String, Object> updateProfile(Authentication authentication) {
        return Map.of("updated", true, "user", authentication.getName());
    }

    @GetMapping("/browser/admin/report")
    public Map<String, Object> adminReport(Authentication authentication) {
        return Map.of("report", "admin", "user", authentication.getName());
    }
}
