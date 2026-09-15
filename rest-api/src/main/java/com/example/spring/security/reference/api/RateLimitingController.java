package com.example.spring.security.reference.api;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequestMapping("/rate-limit")
public class RateLimitingController {

    private final DependencyOutageSimulator dependencyOutageSimulator;

    public RateLimitingController(DependencyOutageSimulator dependencyOutageSimulator) {
        this.dependencyOutageSimulator = dependencyOutageSimulator;
    }

    @GetMapping("/public")
    public String pub() {
        return "ok";
    }

    @GetMapping("/private")
    public String pvt(@AuthenticationPrincipal Jwt jwt) {
        return "hello " + jwt.getSubject();
    }

    @GetMapping("/fail/{policy}")
    public ResponseEntity<String> failPolicy(@PathVariable String policy) {
        try {
            dependencyOutageSimulator.simulateCall(Duration.ofMillis(200));
            return ResponseEntity.ok("downstream ok");
        } catch (IllegalStateException exception) {
            if ("open".equalsIgnoreCase(policy)) {
                return ResponseEntity.ok("fallback");
            }
            return ResponseEntity.status(503).body("downstream unavailable");
        }
    }
}
