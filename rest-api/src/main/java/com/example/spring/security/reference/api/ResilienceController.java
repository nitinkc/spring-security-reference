package com.example.spring.security.reference.api;

import com.example.spring.security.reference.commonsecurity.InMemoryOpaqueTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@RestController
@RequestMapping("/resilient")
public class ResilienceController {

    private final InMemoryOpaqueTokenRepository repository;
    private final DependencyOutageSimulator outageSimulator;

    public ResilienceController(InMemoryOpaqueTokenRepository repository, DependencyOutageSimulator outageSimulator) {
        this.repository = repository;
        this.outageSimulator = outageSimulator;
    }

    @PostMapping("/issue")
    public Map<String, Object> issue(@RequestParam String subject) {
        Instant expiresAt = Instant.now().plus(5, ChronoUnit.MINUTES);
        String token = repository.issue(subject, "resilience-client", expiresAt, "USER");
        return Map.of("access_token", token, "token_type", "Bearer");
    }

    @PostMapping("/mode")
    public Map<String, Object> setMode(@RequestParam DependencyOutageSimulator.Mode value) {
        outageSimulator.setMode(value);
        return Map.of("mode", value);
    }

    @GetMapping("/data")
    public String data(Principal principal) {
        return "resilient data for " + principal.getName();
    }
}
