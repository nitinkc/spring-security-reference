package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.InMemoryOpaqueTokenRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * Test endpoints for the opaque-token lab.
 *
 * This is a learning controller, not a real authorization server. It issues
 * opaque reference tokens, performs local introspection, and supports manual
 * revocation for the lab.
 */
@RestController
@RequestMapping("/op")
public class OpaqueTokenController {

    private final InMemoryOpaqueTokenRepository repository;

    public OpaqueTokenController(InMemoryOpaqueTokenRepository repository) {
        this.repository = repository;
    }

    @PostMapping("/issue")
    public Map<String, Object> issue(@RequestParam String subject,
                                     @RequestParam(required = false, defaultValue = "USER") String scope) {
        Instant expiresAt = Instant.now().plus(5, ChronoUnit.MINUTES);
        String token = repository.issue(subject, "op-client", expiresAt, scope);
        return Map.of("access_token", token, "token_type", "Bearer", "expires_in", 300);
    }

    @PostMapping("/revoke")
    public Map<String, Object> revoke(@RequestParam String token) {
        boolean removed = repository.revoke(token);
        return Map.of("revoked", removed);
    }

    @RequestMapping(value = "/introspect", produces = "application/json")
    public Map<String, Object> introspect(@RequestParam String token) {
        InMemoryOpaqueTokenRepository.OpaqueTokenRecord record = repository.introspect(token);

        if (record == null || !record.active()) {
            return Map.of("active", false);
        }

        return Map.of(
            "active", true,
            "sub", record.subject(),
            "client_id", record.clientId(),
            "exp", record.expiresAt().getEpochSecond(),
            "scope", String.join(" ", record.scopes())
        );
    }
}
