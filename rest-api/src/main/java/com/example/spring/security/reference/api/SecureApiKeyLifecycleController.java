package com.example.spring.security.reference.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/apikey-life")
public class SecureApiKeyLifecycleController {

    private final SecureApiKeyService apiKeyService;

    public SecureApiKeyLifecycleController(SecureApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @PostMapping("/issue")
    public Map<String, Object> issue(@RequestParam String subject,
                                     @RequestParam String scopes,
                                     @RequestParam(required = false, defaultValue = "300") long ttlSeconds) {
        SecureApiKeyService.IssueResult result = apiKeyService.issue(subject,
                Arrays.asList(scopes.split(",")),
                Duration.ofSeconds(ttlSeconds),
                null);
        return Map.of("fullKey", result.fullKey(), "prefix", result.prefix());
    }

    @PostMapping("/issue-expired")
    public Map<String, Object> issueExpired(@RequestParam String subject,
                                            @RequestParam String scopes) {
        SecureApiKeyService.IssueResult result = apiKeyService.issue(subject,
                Arrays.asList(scopes.split(",")),
                Duration.ofSeconds(0),
                Instant.now().minusSeconds(1));
        return Map.of("fullKey", result.fullKey(), "prefix", result.prefix());
    }

    @PostMapping("/revoke")
    public Map<String, Object> revoke(@RequestParam String prefix) {
        boolean removed = apiKeyService.revoke(prefix);
        return Map.of("revoked", removed);
    }

    @PostMapping("/rotate")
    public Map<String, Object> rotate(@RequestParam String prefix) {
        SecureApiKeyService.IssueResult result = apiKeyService.rotate(prefix);
        return Map.of("fullKey", result.fullKey(), "prefix", result.prefix());
    }

    @GetMapping("/user")
    public String user() {
        return "secure-api-key user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "secure-api-key admin";
    }
}
