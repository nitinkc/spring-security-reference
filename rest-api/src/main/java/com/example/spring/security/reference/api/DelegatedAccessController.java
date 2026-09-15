package com.example.spring.security.reference.api;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class DelegatedAccessController {

    @GetMapping("/delegated/data")
    public String data(@AuthenticationPrincipal Jwt jwt) {
        String subject = jwt.getSubject();
        Map<String, Object> actClaim = jwt.getClaimAsMap("act");
        if (actClaim == null) {
            return "data for " + subject;
        }
        return "data for " + subject + " via " + actClaim.get("sub");
    }
}
